import argparse
import logging
from functools import reduce, partial, partialmethod
import re
import subprocess
import ipaddress
import concurrent.futures
import os
import networkx as nx
import hashlib
from pyvis.network import Network
from kubernetes import client, config
from kubernetes.stream import stream
import traceback
logger = None


REGEXP = re.compile(r'(?P<ip_listen>(?:[a-fA-F0-9:]+:)?(?:(?:[0-9]\.?){1,3}){4})(?::)(?P<port_listen>[0-9]{1,6}|\*)(?:\s+)(?P<ip_foreign>(?:[a-fA-F0-9:]+:)?(?:(?:[0-9]\.?){1,3}){4})(?::)(?P<port_foreign>[0-9]{1,6}|\*)(?:\s+)')

def _parse_netstat(output):
    connections = {}
    output = output.strip().split("\n")

    for line in output:
        if line.startswith("tcp") or line.startswith("udp"):
            try:
                line = re.search(REGEXP, line).groupdict()
            except:
                logger.trace(f"Line '{line}' is not matching regexp")
                continue


            ip_src = ipaddress.ip_address(line["ip_listen"])
            ip_dst = ipaddress.ip_address(line["ip_foreign"])
            logger.trace(f"Found: '{ip_src}' / '{ip_dst}'")
    
            try:
                ip_src = ip_src.ipv4_mapped
                logger.trace(f"IP src '{ip_src}' is an ipv6 or 6to4, converting")
            except:
                logger.trace(f"IP src '{ip_src}' is an ipv4")
            try:
                ip_dst = ip_dst.ipv4_mapped
                logger.trace(f"IP dst '{ip_dst}' is an ipv6 or 6to4, converting")
            except:
                logger.trace(f"IP dst '{ip_dst}' is an ipv4")

            if str(ip_dst) == '127.0.0.1' or str(ip_src) == '127.0.0.1' or str(ip_src) == '0.0.0.0':
                logger.trace(f"Ignoring {ip_src} :: {ip_dst} , local address or listen")
                continue


            if not ip_dst.is_private:
                logger.critical(f"Ignoring {ip_dst} because it's not a private ip")
                continue

            if int(line['port_listen']) > 32768:
                pass #plustard
            else:
                print(f"{ip_dst}")
                connections.setdefault(f"{line['port_listen']}", []).append(str(ip_dst))

    connections = {k: list(set(v)) for k, v in connections.items()}

    return connections


def _run_netstats(kube_api, namespace, pod):
    logger.info(f"Retrieving netstats for {namespace}/{pod.metadata.name}")

    connections = {}
    for container in pod.spec.containers:
        container = container.name
        logger.info(f"Testing: {namespace}/{pod.metadata.name}/{container}")
        exec_netstat_command = ['netstat', '-npatu']
        exec_ss_command = ['ss', '-npatu']
        try:
            resp = stream(
                kube_api.connect_get_namespaced_pod_exec,
                name=pod.metadata.name, namespace=namespace, container=container,
                command=exec_netstat_command,
                stderr=True, stdin=False,
                stdout=True, tty=False
            )
            if "file not found" in resp:
                resp = stream(
                    kube_api.connect_get_namespaced_pod_exec,
                    name=pod.metadata.name, namespace=namespace, container=container,
                    command=exec_ss_command,
                    stderr=True, stdin=False,
                    stdout=True, tty=False
                )
            logger.debug(_parse_netstat(resp))
            connections |= _parse_netstat(resp)
        except Exception as e:
            logger.error(f"Cannot connect to {namespace}/{pod.metadata.name}/{container}: '{e}'")

        logger.debug(connections)

    return connections


def get_netstats(kube_api, pod_list):
    for group_name, pods in pod_list.copy().items():
        for i, pod in enumerate(pods["pods"]):
            pod_list[group_name].setdefault("connections", {})
            pod_list[group_name]["connections"] |= _run_netstats(kube_api, pods["namespace"], pod)

    return pod_list

def get_pods(kube_api, namespaces, all_ns):
     # kubectl get pods -n netbox -o name

    pods = {}

    for elem in all_ns.items:
        if elem.metadata.namespace not in namespaces:
            continue
        short_pod_name = elem.metadata.name.split("-")
        short_pod_name = "-".join(
            short_pod_name[:-2] if len(short_pod_name[-1]) == 5 and len(short_pod_name[-2]) >= 9 else short_pod_name
        )
        if not elem.status.container_statuses[0].started:
            logger.info(f"IGN: {elem.metadata.name}, status not started")
            continue
        
        pods.setdefault(short_pod_name, {
            "namespace": elem.metadata.namespace,
            "pods": [],
            "ips": []
        })

        logger.debug(f"{short_pod_name} {elem.metadata.name}")
        pods[short_pod_name]["pods"].append(elem)
        pods[short_pod_name]["ips"].append(elem.status.pod_ip)

    
    return get_netstats(kube_api, pods)


def get_pod_by_ip(pods_list, ip, all_ns):
    for group_name, pods in pods_list.items():
        if ip in pods["ips"]:
            return f'{pods["namespace"]}/{group_name}'
    for item in all_ns.items:
        if ip == item.status.pod_ip:
            short_pod_name = item.metadata.name.split("-")
            short_pod_name = "-".join(
                short_pod_name[:-2] if len(short_pod_name[-1]) == 5 and len(short_pod_name[-2]) >= 9 else short_pod_name
            )            
            return f'{item.metadata.namespace}/{short_pod_name}'
         
            

def draw_pods(namespaces):
    config.load_kube_config()
    kube_api = client.CoreV1Api()
    all_ns = kube_api.list_pod_for_all_namespaces(watch=False)
    pods_list = get_pods(kube_api, namespaces, all_ns)

    net = Network('768px', '1366px', directed=True)
    # create all nodes firsts
    for group_name, pods in pods_list.items():
        color = hashlib.md5(bytes(pods["namespace"].encode("utf8"))).hexdigest()[:6]
        net.add_node(f"{pods['namespace']}/{group_name}", title=",".join(pods["ips"]), color=f"#{color}")

    for group_name, pods in pods_list.items():
        for port, ips in pods["connections"].items():
            for ip in ips:
                dest_pod = get_pod_by_ip(pods_list, ip, all_ns)
                try:
                    net.get_node(dest_pod)
                except:
                    if not dest_pod:
                        dest_pod = ip
                    if dest_pod.split("/")[0] == pods["namespace"]:
                        color = hashlib.md5(bytes(pods["namespace"].encode("utf8"))).hexdigest()[:6]
                    else:
                        color = hashlib.md5(bytes(dest_pod.split("/")[0].encode("utf8"))).hexdigest()[:6]
                    net.add_node(dest_pod, title=ip, color=f"#{color}")
                    net.add_edge(
                        dest_pod, f"{pods['namespace']}/{group_name}",
                        label=f":{port}", arrowStrikethrough=True
                    )
                else:
                    net.add_edge(dest_pod, f"{pods['namespace']}/{group_name}",
                                 label=f":{port}", arrowStrikethrough=True)

    net.show("test.html")
    

def main():
    """
    Main program
    """
    global logger

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--log", dest="verbose", choices=['TRACE', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help="increase verbosity")
    parser.add_argument("-n", "--namespaces", help="list of namespaces to topo", nargs="+", action="append")
    args = parser.parse_args()

    namespaces = reduce(
        lambda a, b: a + b if isinstance(a, list) else [a] + b,
        args.namespaces
    )

    logger = logging.getLogger()


    logging.TRACE = 5
    logging.addLevelName(logging.TRACE, 'TRACE')
    logging.Logger.trace = partialmethod(logging.Logger.log, logging.TRACE)
    logging.trace = partial(logging.log, logging.TRACE)
    
    logging.addLevelName(logging.TRACE, "\033[1;35m%s\033[1;0m" % logging.getLevelName(logging.TRACE))
    logging.addLevelName(logging.INFO, "\033[1;32m%s\033[1;0m" % logging.getLevelName(logging.INFO))
    logging.addLevelName(logging.DEBUG, "\033[1;34m%s\033[1;0m" % logging.getLevelName(logging.DEBUG))
    logging.addLevelName(logging.WARNING, "\033[1;31m%s\033[1;0m" % logging.getLevelName(logging.WARNING))
    logging.addLevelName(logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))

    if args.verbose:
        logging.basicConfig(level=logging.getLevelName(args.verbose))
    else:
        logging.basicConfig(level=logging.WARNING)


    draw_pods(namespaces)


if __name__ == "__main__":
    main()
