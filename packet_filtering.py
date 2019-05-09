"""
Name: icmp_packet_filtering.py

TODO give purpose of module
TODO rename module
"""

from collections import defaultdict
import os
import pyshark
import re
import matplotlib.pyplot as plt


class FileNotFoundError(OSError):
    pass


def get_file_cap_from_pcap_file(pcap_file):
    """
    A function that gets a FileCapture object from a .pcap file, containing
    all the packets captured in the file.
    :param pcap_file: A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :return:          A FileCapture object.
    """
    if not os.path.exists(pcap_file):
        raise FileNotFoundError
    if not pcap_file.endswith('.pcap'):
        raise FileNotFoundError('The file extension must be .pcap')

    file_cap = pyshark.FileCapture(input_file=pcap_file)

    return file_cap


def filter_pkts_src_ip(file_cap, src_ip_addr):
    """
    A function to filter a list of packets based on the source IP address.
    :param file_cap:       A FileCapture object or a list of
                           pyshark.packet.packet.Packet objects.
    :param src_ip_addr:    The source IP address.
    :return:               A list of packets, filtered on the source IP
                           address.
    """
    list_pkts = []
    for pkt in file_cap:
        try:
            if pkt.ip.src == src_ip_addr:
                list_pkts.append(pkt)
        # If a packet doesn't have an IP layer, we skip it.
        except AttributeError:
            pass

    return list_pkts


def filter_pkts_dst_ip(file_cap, dst_ip_addr):
    """
    A function to filter a list of packets based on the destination IP
    address.
    :param file_cap:       A FileCapture object or a list of
                           pyshark.packet.packet.Packet objects.
    :param dst_ip_addr:    The destination IP address.
    :return:               A list of packets, filtered on the destination IP
                           address.
    """
    list_pkts = []
    for pkt in file_cap:
        try:
            if pkt.ip.dst == dst_ip_addr:
                list_pkts.append(pkt)
        # If a packet doesn't have an IP layer, we skip it.
        except AttributeError:
            pass

    return list_pkts


def filter_pkts_src_dst_ip(file_cap, src_ip_addr, dst_ip_addr):
    """
    A function to filter a list of packets based on the source and destination
    IP address.
    :param file_cap:       A FileCapture object or a list of
                           pyshark.packet.packet.Packet objects.
    :param src_ip_addr:    The source IP address.
    :param dst_ip_addr:    The destination IP address.
    :return:               A list of packets, filtered on the source and
                           destination IP address.
    """
    list_pkts = []
    for pkt in file_cap:
        try:
            if pkt.ip.src == src_ip_addr and pkt.ip.dst == dst_ip_addr:
                list_pkts.append(pkt)
        # If a packet doesn't have an IP layer, we skip it.
        except AttributeError:
            pass

    return list_pkts


def filter_pkts_icmp(file_cap):
    """
    A function to filter a list of packets to get the ICMP packets.
    :param file_cap:   A FileCapture object or a list of
                       pyshark.packet.packet.Packet objects.
    :return:           A list of ICMP packets
    """
    list_icmp_pkts = []
    for pkt in file_cap:
        try:
            if pkt.icmp:
                list_icmp_pkts.append(pkt)
        # If a packet doesn't have an ICMP layer, we skip it.
        except AttributeError:
            pass

    return list_icmp_pkts


def filter_icmp_pkts_mpls_encaps(list_icmp_pkts):
    """
    A function to filter a list of ICMP packets to get the MPLS
    encapsulated packets.
    :param list_icmp_pkts:   A list of pyshark.packet.packet.Packet objects
                             that are ICMP packets.
    :return:                 A list of ICMP packets with MPLS encapsulation.
    """
    list_icmp_mpls_pkts = []
    for pkt in list_icmp_pkts:
        try:
            if pkt.icmp:
                list_icmp_mpls_pkts.append(pkt)
        # If a packet doesn't have an ICMP layer, we skip it.
        except AttributeError:
            pass

    return list_icmp_mpls_pkts


def filter_icmp_pkts_requests(list_icmp_pkts):
    """
    A function to filter a list of ICMP packets to get the ICMP requests.
    :param list_icmp_pkts:   A list of pyshark.packet.packet.Packet objects
                             that are ICMP packets.
    :return:                 A list of ICMP request packets.
    """
    list_icmp_requests = []
    for pkt in list_icmp_pkts:
        try:
            # The ICMP type for an echo reply is '8'. See
            # https://www.iana.org/assignments/icmp-parameters/
            # icmp-parameters.xhtml for more details.
            if pkt.icmp.type == '8':
                list_icmp_requests.append(pkt)
        except AttributeError as error:
            print(error)
            print('Check whether the input list contains only ICMP packets')

    return list_icmp_requests


def filter_icmp_pkts_replies(list_icmp_pkts):
    """
    A function to filter a list of ICMP packets to get the ICMP reply.
    :param list_icmp_pkts:   A list of pyshark.packet.packet.Packet objects
                             that are ICMP packets.
    :return:                 A list of ICMP reply packets.
    """
    list_icmp_replies = []
    for pkt in list_icmp_pkts:
        try:
            # The ICMP type for an echo reply is '0'. See
            # https://www.iana.org/assignments/icmp-parameters/
            # icmp-parameters.xhtml for more details.
            if pkt.icmp.type == '0':
                list_icmp_replies.append(pkt)
        except AttributeError as error:
            print(error)
            print('Check whether the input list contains only ICMP packets')

    return list_icmp_replies


def get_icmp_requests_src_ip(pcap_file, src_ip_addr):
    """
    A function to get list of all the ICMP requests sent from a given source
    IP address.
    :param pcap_file:    A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param src_ip_addr:  The source IP address.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_src_ip_pkts = filter_pkts_src_ip(file_cap, src_ip_addr)
    list_icmp_pkts = filter_pkts_icmp(list_src_ip_pkts)
    list_icmp_src_ip_pkts = filter_icmp_pkts_requests(list_icmp_pkts)

    return list_icmp_src_ip_pkts


def get_icmp_requests_src_dest_ip(pcap_file, src_ip_addr, dst_ip_addr):
    """
    A function to get list of all the ICMP requests sent from a given source
    IP address to a given IP address.
    :param pcap_file:    A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param src_ip_addr:  The source IP address.
    :param dst_ip_addr:  The destination IP address.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_src_dst_ip_pkts = filter_pkts_src_dst_ip(file_cap, src_ip_addr, dst_ip_addr)
    list_icmp_pkts = filter_pkts_icmp(list_src_dst_ip_pkts)
    list_icmp_src_dst_ip_pkts = filter_icmp_pkts_requests(list_icmp_pkts)

    return list_icmp_src_dst_ip_pkts


def get_icmp_replies_dst_ip(pcap_file, dst_ip_addr):
    """
    A function to get list of all the ICMP replies received at a given
    destination IP address.
    :param pcap_file:    A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param dst_ip_addr:  The destination IP address.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_dst_ip_pkts = filter_pkts_dst_ip(file_cap, dst_ip_addr)
    list_icmp_pkts = filter_pkts_icmp(list_dst_ip_pkts)
    list_icmp_dst_ip_pkts = filter_icmp_pkts_replies(list_icmp_pkts)

    return list_icmp_dst_ip_pkts


def get_icmp_stats_from_list(list_icmp_pkts):
    """
    A function to get stats for the number of ICMP echo requests and replies
    received from a list of ICMP packets
    :param list_icmp_pkts:   A list of pyshark.packet.packet.Packet objects
                             that are ICMP packets.
    :return:
    """
    icmp_request_stats = defaultdict(int)
    icmp_reply_stats = defaultdict(int)
    list_icmp_request_pkts = filter_icmp_pkts_requests(list_icmp_pkts)
    list_icmp_reply_pkts = filter_icmp_pkts_replies(list_icmp_pkts)

    for request_pkt in list_icmp_request_pkts:
        src_ip_addr = request_pkt.ip.src
        icmp_request_stats[src_ip_addr] += 1

    for reply_pkt in list_icmp_reply_pkts:
        dst_ip_addr = reply_pkt.ip.dst
        icmp_reply_stats[dst_ip_addr] += 1

    return icmp_request_stats, icmp_reply_stats


def get_icmp_stats_ip_from_list(list_icmp_pkts, ip_addr):
    """
    A function to get stats for the number of ICMP echo requests and replies
    received for a given IP address.
    :param list_icmp_pkts:   A list of pyshark.packet.packet.Packet objects
                             that are ICMP packets.
    :param ip_addr:          The relevant IP address.
    :return:
    """
    icmp_sent_to_stats = defaultdict(int)
    icmp_rcvd_from_stats = defaultdict(int)
    list_icmp_request_pkts = filter_icmp_pkts_requests(list_icmp_pkts)
    list_icmp_reply_pkts = filter_icmp_pkts_replies(list_icmp_pkts)
    list_icmp_request_ip_pkts = filter_pkts_src_ip(list_icmp_request_pkts, ip_addr)
    list_icmp_reply_ip_pkts = filter_pkts_dst_ip(list_icmp_reply_pkts, ip_addr)

    for request_pkt in list_icmp_request_ip_pkts:
        dst_ip_addr = request_pkt.ip.dst
        icmp_sent_to_stats[dst_ip_addr] += 1

    for reply_pkt in list_icmp_reply_ip_pkts:
        src_ip_addr = reply_pkt.ip.src
        icmp_rcvd_from_stats[src_ip_addr] += 1

    return icmp_sent_to_stats, icmp_rcvd_from_stats


def get_icmp_stats_from_pcap(pcap_file):
    """
    A function to get stats for the number of ICMP echo requests sent and replies
    received from a given pcap file.
    :param pcap_file:    A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_icmp_pkts = filter_pkts_icmp(file_cap)
    icmp_request_stats, icmp_reply_stats = get_icmp_stats_from_list(list_icmp_pkts)

    return icmp_request_stats, icmp_reply_stats


def get_icmp_stats_ip_from_pcap(pcap_file, ip_addr):
    """
    A function to get stats for the number of ICMP echo requests sent and replies
    received from a given pcap file for a given IP address.
    :param pcap_file:    A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param ip_addr:      The relevant IP address.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_icmp_pkts = filter_pkts_icmp(file_cap)
    icmp_sent_to_stats, icmp_rcvd_from_stats = get_icmp_stats_ip_from_list(list_icmp_pkts, ip_addr)

    return icmp_sent_to_stats, icmp_rcvd_from_stats


def get_list_icmp_requests_no_response(pcap_file):
    """
    A function to get a list of ICMP requests that have no response.
    :param pcap_file:   A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :return:            A list of ICMP requests that have no response.
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_icmp_pkts = filter_pkts_icmp(file_cap)
    list_icmp_req_pkts = filter_icmp_pkts_requests(list_icmp_pkts)
    list_icmp_reply_pkts = filter_icmp_pkts_replies(list_icmp_pkts)
    list_icmp_req_no_reply = []

    dict_reply_ident_seq = defaultdict(list)
    for reply_pkt in list_icmp_reply_pkts:
        if reply_pkt.icmp.ident != 0:
            dict_reply_ident_seq[reply_pkt.icmp.ident].append(reply_pkt.icmp.seq)

    for req_pkt in list_icmp_req_pkts:
        ident = req_pkt.icmp.ident
        seq = req_pkt.icmp.seq
        if not seq in dict_reply_ident_seq[ident]:
            list_icmp_req_no_reply.append(req_pkt)

    return list_icmp_req_no_reply


def convert_time_ns_ms(timestamp_ns):
    """
    A function to convert a timestamp with nanoseconds into a timestamp with
    milliseconds.
    :param timestamp_ns: A timestamp in the format HH:MM:SS.XXXXXXXXX.
    :return:             A simplified timestamp, with milliseconds rather
                         than nanoseconds.
    """
    ms = timestamp_ns[:-6]  # Remove 6 digits to convert nano to milliseconds.
    return ms


def simplify_long_timestamp(long_timestamp):
    """
    A function to simplify a timestamp into HH:MM:SS.XXXXXX format.
    We convert it into microsecond format because the datetime.strptime
    function can't deal with smaller increments of time than microseconds.
    :param long_timestamp: A string with a full timestamp, including the
                           time in a HH:MM:SS.XXXXXXXXX.
    :return:               A simplified timestamp.
    """
    match = re.search('(2[0-3]|[01]?[0-9]):'        # Match on hours
                      '([0-5]?[0-9]):'              # Match on minutes
                      '([0-5]?[0-9]).'              # Match on seconds
                      '([0-9])+', long_timestamp)   # Match on nanoseconds

    if match:
        simple_time = str(match.group(0))
        simple_time = convert_time_ns_ms(simple_time)
    else:
        simple_time = None

    return simple_time


def get_timestamp_from_pkt(pkt):
    """
    A function to get a timestamp from a packet
    :param pkt: A pyshark.packet.packet.Packet object.
    :return:    A string containing the timestamp the pkt arrived.
    """
    long_time = pkt.frame_info.time
    simple_time = simplify_long_timestamp(long_time)

    return simple_time


def count_num_miss_pings_per_ip(pcap_file):
    """
    A function to count the number of ICMP pings that didn't get a response
    per source IP address
    :param pcap_file: A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :return:
    """
    list_miss_pings = get_list_icmp_requests_no_response(pcap_file)
    dict_miss_pings = defaultdict(int)

    for pkt in list_miss_pings:
        src_ip_addr = pkt.ip.src
        dict_miss_pings[src_ip_addr] += 1

    return dict_miss_pings


def plot_scatter_graph_from_dict(graph_dict, xlabel, ylabel, title, save_name):
    """
    A function to plot a line graph, given a dictionary with suitable
    key/value pairs.
    :param graph_dict:   The dictionary with data to plot.
    :param xlabel:       The label for the x-axis.
    :param ylabel:       The label for the y-axis.
    :param title:        The title of the graph.
    :param save_name:    The name of the file we save to store the picture.
    :return:             Nothing. But we will save the figure in a local
                         directory.
    """
    plt.interactive(False)
    key_list = graph_dict.keys()
    value_list = graph_dict.values()
    plt.scatter(key_list, value_list)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(fontsize=7, rotation=90)
    plt.subplots_adjust(bottom=0.5)
    plt.title(title)
    plt.savefig(save_name)

    return


def plot_missing_pings(pcap_file, plot_title):
    """
    A function that plots the timestamp of missing pings.
    :param pcap_file:  A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param plot_title: The name of the plot
    :return:
    """
    list_miss_pings = get_list_icmp_requests_no_response(pcap_file)
    dict_miss_pings = defaultdict(int)

    for pkt in list_miss_pings:
        time = get_timestamp_from_pkt(pkt)
        dict_miss_pings[time] = 1

    plot_scatter_graph_from_dict(dict_miss_pings,
                                 'Timestamp',
                                 'Missing Ping',
                                 plot_title,
                                 '%s.png' % plot_title)

    return
