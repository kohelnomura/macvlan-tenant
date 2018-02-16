package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ipam"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
	"github.com/davecgh/go-spew/spew"
	dockerclient "github.com/docker/docker/client"
	"github.com/j-keck/arping"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"log"
	"os"
)

var logger = log.New(os.Stderr, "", 0)

const (
	IPv4InterfaceArpProxySysctlTemplate = "net.ipv4.conf.%s.proxy_arp"
)

type NetConf struct {
	types.NetConf
	Manage string `json:"manage"`
	Service string `json:"service"`
	Mode   string `json:"mode"`
	MTU    int    `json:"mtu"`
}

func newClient() (kubernetes.Interface, error) {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", "/root/.kube/config")
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(kubeConfig)
}

func init() {
	runtime.LockOSThread()
}

func loadConf(bytes []byte) (*NetConf, string, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	if n.Service == "" {
		return nil, "", fmt.Errorf(`"service" field is required.`)
	}
	return n, n.CNIVersion, nil
}

func modeFromString(s string) (netlink.MacvlanMode, error) {
	switch s {
	case "", "bridge":
		return netlink.MACVLAN_MODE_BRIDGE, nil
	case "private":
		return netlink.MACVLAN_MODE_PRIVATE, nil
	case "vepa":
		return netlink.MACVLAN_MODE_VEPA, nil
	case "passthru":
		return netlink.MACVLAN_MODE_PASSTHRU, nil
	default:
		return 0, fmt.Errorf("unknown macvlan mode: %q", s)
	}
}

func createMacvlan(conf *NetConf, ifName string, netns ns.NetNS, parentIf string) (*current.Interface, error) {
	macvlan := &current.Interface{}

	mode, err := modeFromString(conf.Mode)
	if err != nil {
		return nil, err
	}

	logger.Printf("[NOMURA] create macvlan on %v", parentIf)
	m, err := netlink.LinkByName(parentIf)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup master %q: %v", parentIf, err)
	}

	tmpName, err := ip.RandomVethName()
	if err != nil {
		return nil, err
	}

	mv := &netlink.Macvlan{
		LinkAttrs: netlink.LinkAttrs{
			MTU:         conf.MTU,
			Name:        tmpName,
			ParentIndex: m.Attrs().Index,
			Namespace:   netlink.NsFd(int(netns.Fd())),
		},
		Mode: mode,
	}

	if err := netlink.LinkAdd(mv); err != nil {
		return nil, fmt.Errorf("failed to create macvlan: %v", err)
	}

	err = netns.Do(func(_ ns.NetNS) error {
		ipv4SysctlValueName := fmt.Sprintf(IPv4InterfaceArpProxySysctlTemplate, tmpName)
		if _, err := sysctl.Sysctl(ipv4SysctlValueName, "1"); err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to set proxy_arp on newly added interface %q: %v", tmpName, err)
		}

		err := ip.RenameLink(tmpName, ifName)
		if err != nil {
			_ = netlink.LinkDel(mv)
			return fmt.Errorf("failed to rename macvlan to %q: %v", ifName, err)
		}
		macvlan.Name = ifName

		contMacvlan, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to refetch macvlan %q: %v", ifName, err)
		}
		macvlan.Mac = contMacvlan.Attrs().HardwareAddr.String()
		macvlan.Sandbox = netns.Path()

		return nil
	})
	if err != nil {
		return nil, err
	}

	return macvlan, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	n, cniVersion, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", netns, err)
	}
	defer netns.Close()

	ctx := context.Background()
	cli, errDocker := dockerclient.NewEnvClient()
	if errDocker != nil {
		panic(errDocker)
	}
	cli.NegotiateAPIVersion(ctx)
	json, dockerclienterr := cli.ContainerInspect(ctx, args.ContainerID)
	if dockerclienterr != nil {
		return dockerclienterr
	}
	logger.Printf("[NOMURA] start creating macvlan of container: %v", json.Config.Hostname)

	client, err := newClient()
	if err != nil {
		log.Fatal(err)
	}
	pods, err := client.CoreV1().Pods("").List(meta_v1.ListOptions{})
	if err != nil {
		log.Fatal(err)
	}
	var ibmvlanid string
	var ibmip string
	//var ibmgw string
	var routesArray []string
	for _, pod := range pods.Items {
		if pod.Name == json.Config.Hostname {
			//if pod.Name == "busybox1" {
			ibmvlanid = pod.Annotations["ccc.ibm.co.jp/vlanid"]
			ibmip = pod.Annotations["ccc.ibm.co.jp/ip"]
			routesArray = strings.Split(pod.Annotations["ccc.ibm.co.jp/routes"], ";")
			//			ibmgw = pod.Annotations["ccc.ibm.co.jp/gw"]
			logger.Printf("[NOMURA] !trace vlanid >>>>>>>>>>>>>>>>>>>>>----------%v\n", ibmvlanid)
			logger.Printf("[NOMURA] !trace ip >>>>>>>>>>>>>>>>>>>>>----------%v\n", ibmip)
			logger.Printf("[NOMURA] !trace route >>>>>>>>>>>>>>>>>>>>>----------%v\n", routesArray)
			//			logger.Printf("[NOMURA] !trace gw >>>>>>>>>>>>>>>>>>>>>----------%v\n", ibmgw)
		}
	}

	var routes []*types.Route
	for i := 0; i < len(routesArray); i++ {
		rStr := routesArray[i]
		if rStr != "" {
			routeInf := strings.Split(rStr, "->")
			_, targetnw, err := net.ParseCIDR(routeInf[0])
			routegw, _, err := net.ParseCIDR(routeInf[1])
			if err != nil {
				return err
			}
			route := types.Route{Dst: *targetnw, GW: routegw}
			routes = append(routes, &route)
		}
	}
	var parentIf string
	if ibmvlanid != "" {
		parentIf = n.Service + "." + ibmvlanid
	} else {
		parentIf = n.Manage
	}
	macvlanInterface, err := createMacvlan(n, args.IfName, netns, parentIf)

	if err != nil {
		return err
	}

	ipv4, err := types.ParseCIDR(ibmip)
	//_, routev4, err := net.ParseCIDR("10.96.0.1/24")
	//routegwv4, _, err := net.ParseCIDR("10.91.111.113/24")
	if err != nil {
		return err
	}
	r := &current.Result{
		IPs: []*current.IPConfig{
			{
				Version: "4",
				Address: *ipv4,
				//				Gateway: net.ParseIP(ibmgw),
			},
		},
		//	Routes: []*types.Route{
		//		{Dst: *routev4, GW: routegwv4},
		//   },
		DNS: types.DNS{
			Nameservers: []string{},
			Domain:      "",
			Search:      []string{},
			Options:     []string{},
		},
	}

	result, err := current.NewResultFromResult(r)
	result.Routes = routes
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}
	result.Interfaces = []*current.Interface{macvlanInterface}

	for _, ipc := range result.IPs {
		ipc.Interface = current.Int(0)
	}
	err = netns.Do(func(_ ns.NetNS) error {
		if err := ipam.ConfigureIface(args.IfName, result); err != nil {
			return err
		}
		contVeth, err := net.InterfaceByName(args.IfName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", args.IfName, err)
		}
		for _, ipc := range result.IPs {
			if ipc.Version == "4" {
				_ = arping.GratuitousArpOverIface(ipc.Address.IP, *contVeth)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	result.DNS = n.DNS
	logger.Printf("[NOMURA] IF result       ----------%v\n", spew.Sdump(result))
	return types.PrintResult(result, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	_, _, err := loadConf(args.StdinData)
	if err != nil {
		return err
	}

	//err = ipam.ExecDel(n.IPAM.Type, args.StdinData)
	//if err != nil {
	//	return err
	//}

	if args.Netns == "" {
		return nil
	}

	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		if err := ip.DelLinkByName(args.IfName); err != nil {
			if err != ip.ErrLinkNotFound {
				return err
			}
		}
		return nil
	})

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
