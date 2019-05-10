"""
Name: icmp_packet_filtering.py

This module contains functions for filtering ICMP packets and plotting
useful information.
"""

from collections import defaultdict
from collections import OrderedDict
from packet_filtering import convert_dict_to_table
from packet_filtering import get_file_cap_from_pcap_file
from packet_filtering import get_timestamp_from_pkt
from packet_filtering import plot_scatter_graph_from_dict


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
            # The ICMP type for an echo request is '8'. See
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


def get_lists_icmp_req_reply(pcap_file):
    """
    A function that gets two lists. The first is a list of ICMP requests.
    The second is a list of ICMP replies
    :param pcap_file: A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :return:
    """
    file_cap = get_file_cap_from_pcap_file(pcap_file)
    list_icmp_pkts = filter_pkts_icmp(file_cap)
    list_icmp_req_pkts = filter_icmp_pkts_requests(list_icmp_pkts)
    list_icmp_reply_pkts = filter_icmp_pkts_replies(list_icmp_pkts)

    return list_icmp_req_pkts, list_icmp_reply_pkts


def get_list_miss_success_pings(list_ping_req, list_ping_reply):
    """
    A function to get two lists, a list of ICMP pings with no response
    and a list of ICMP pings with a response.
    :param list_ping_req:   A list of ICMP echo requests.
    :param list_ping_reply: A list of ICMP echo replies.
    :return:
    """
    list_miss_pings = get_list_icmp_req_filt_response(list_ping_req,
                                                      list_ping_reply,
                                                      response=False)
    list_success_pings = get_list_icmp_req_filt_response(list_ping_req,
                                                         list_ping_reply,
                                                         response=True)

    return list_miss_pings, list_success_pings


def get_list_icmp_req_filt_response(list_icmp_req, list_icmp_reply, response=True):
    """
    A function to get a list of ICMP requests, filtered based on whether they
    got a response or not.
    :param list_icmp_req:   A list of ICMP echo requests.
    :param list_icmp_reply: A list of ICMP echo replies.
    :param response:        A boolean representing whether or not we want packets
                            that got a response
    :return:                A list of ICMP requests filtered based on whether they
                            got a response or not.
    """
    list_icmp_req_filt = []
    dict_reply_ident_seq = defaultdict(list)
    for reply_pkt in list_icmp_reply:
        # Linux systems use a unique, non-zero, identifier
        # for every ping process initiated by a user.
        # We're only interested in these pings.
        if reply_pkt.icmp.ident != '0':
            dict_reply_ident_seq[reply_pkt.icmp.ident].append(reply_pkt.icmp.seq)

    for req_pkt in list_icmp_req:
        ident = req_pkt.icmp.ident
        seq = req_pkt.icmp.seq
        # Linux systems use a unique, non-zero, identifier
        # for every ping process initiated by a user.
        # We're only interested in these pings.
        if ident != '0':
            if response:
                if seq in dict_reply_ident_seq[ident]:
                    list_icmp_req_filt.append(req_pkt)
            else:
                if seq not in dict_reply_ident_seq[ident]:
                    list_icmp_req_filt.append(req_pkt)

    return list_icmp_req_filt


def save_num_pings_per_ip_to_csv(pcap_file, file_name):
    """
    A function to count the number of ICMP pings that didn't get a response
    per source IP address
    :param pcap_file: A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param file_name:
    :return:
    """
    list_ping_req, list_ping_reply = get_lists_icmp_req_reply(pcap_file)
    list_miss_pings, list_success_pings = get_list_miss_success_pings(list_ping_req,
                                                                      list_ping_reply)
    dict_miss_pings = defaultdict(lambda: defaultdict(int))
    dict_success_pings = defaultdict(lambda: defaultdict(int))

    for pkt in list_miss_pings:
        src_ip_addr = pkt.ip.src
        dst_ip_addr = pkt.ip.dst
        dict_miss_pings[src_ip_addr][dst_ip_addr] += 1

    for pkt in list_success_pings:
        src_ip_addr = pkt.ip.src
        dst_ip_addr = pkt.ip.dst
        dict_success_pings[src_ip_addr][dst_ip_addr] += 1

    convert_dict_to_table(dict_miss_pings, '%s_missing.csv' % file_name)
    convert_dict_to_table(dict_success_pings, '%s_success.csv' % file_name)

    return


def plot_pings(pcap_file, plot_title):
    """
    A function that plots the timestamp of missing pings.
    :param pcap_file:  A .pcap file e.g. C:/my_pcap_files/'my_capture.pcap'.
    :param plot_title: The name of the plot
    :return:
    """
    list_ping_req, list_ping_reply = get_lists_icmp_req_reply(pcap_file)
    list_miss_pings, list_success_pings = get_list_miss_success_pings(list_ping_req,
                                                                      list_ping_reply)
    dict_miss_pings = defaultdict(int)
    dict_success_pings = defaultdict(int)

    for pkt in list_miss_pings:
        time = get_timestamp_from_pkt(pkt)
        dict_miss_pings[time] = 0

    for pkt in list_success_pings:
        time = get_timestamp_from_pkt(pkt)
        dict_success_pings[time] = 1

    plot_dict = dict_miss_pings.copy()
    plot_dict.update(dict_success_pings)
    sorted_plot_dict = OrderedDict(sorted(plot_dict.items(), key=lambda v: v[0]))
    plot_scatter_graph_from_dict(sorted_plot_dict,
                                 'Timestamp',
                                 'Missing Ping',
                                 plot_title,
                                 '%s.png' % plot_title)

    return
