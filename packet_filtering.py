"""
Name: packet_filtering.py

This module contains functions for packet filtering that aren't specific
to any particular protocol.
"""

import matplotlib.pyplot as plt
import pandas
import os
import pyshark
import re


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
    plt.figure()
    plt.scatter(key_list, value_list)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(fontsize=7, rotation=90)
    plt.subplots_adjust(bottom=0.5)
    plt.title(title)
    plt.savefig(save_name)

    return


def convert_dict_to_table(csv_dict, save_name):
    """
    A function to convert a list of dictionaries to a table in a csv file.
    :param csv_dict: A list of dictionaries.
    :param save_name: The name of the csv file.
    :return:
    """
    df = pandas.DataFrame(csv_dict)
    print df
    df.to_csv(save_name)

    return
