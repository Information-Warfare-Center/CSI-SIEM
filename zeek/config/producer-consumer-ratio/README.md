PCR - Producer Consumer Ratio
=====
This script is a Bro implementation of the Producer Consomer Ratio described by Carter Bullard and John Gerth at FloCon 2014.
Their presentation is located at: http://resources.sei.cmu.edu/asset_files/Presentation/2014_017_001_90063.pdf

Purpose
---------
Bullard and Gerth propose that:
* "Data exfiltration is a problem"
* "All network nodes are producers and consumers of data"
* "[Data] exfiltration is a shift in producer / consumer roles"
* "Better methods to describe producer / consumers will really help"

Summary
---------
Bullard and Gerth describe PCR as, "A normalized value indicating directionality of application information transfer, independent of data load or rate."

PCR is a value between -1 and 1. Negative values indicate consumption of data (download) and positive values indicate production (upload) of data.

* -1.0 Consumer <= PCR <= 1.0 Producer

Implementation
---------
This implementation of PCR provides two different metrics:

1. Every flow in the 'conn.log' is appended with a column called 'pcr' that indicates the PCR of the flow
2. All hosts in subnets defined in Site::local_nets have an average 'pcr' value calculated for them on a 1 minute interval


Future work
---------
* Calculate more than one PCR average - one for local networks and another for remote networks

