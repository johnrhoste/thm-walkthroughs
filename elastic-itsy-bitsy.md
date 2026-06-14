# ItsyBitsy

This tutorial covers the TryHackMe challenge *# ItsyBitsy*. In this room, we must investigate an alert triggered by an IDS, and look through network connection logs of a user, to determine if a C2 connection has been established.

Link to room:
https://tryhackme.com/room/itsybitsy

## Task 1: Introduction

Elastic Stack (ELK -- Elasticsearch, Logstash, and Kibana) is particularly popular due to its excellent data searching capabilities and strong visualization options.

While no prerequisites are mentioned, a few rooms exist to become more comfortable with the Elastic Stack.

Other helpful rooms:
* https://tryhackme.com/room/investigatingwithelk101
* https://tryhackme.com/room/servidae

No challenges in this section — simply deploy the lab machine and wait a few minutes. When the IP for the machine is revealed, open up Elastic in your browser. Log in using the credentials provided (this should happen automatically) and navigate to the `Discover` tab.

<img width="1088" height="444" alt="Screen Shot 2026-06-13 at 8 18 02 PM" src="https://github.com/user-attachments/assets/2850dba6-bc82-4dfe-a94b-24d550351ae3" />

## Task 2: 

In this investigation, we're focused on the user `Browne`, from the HR department, who accessed a suspicious file. For this challenge, only the connection logs were taken, and they've been ingested into the `connection_logs` index in Kibana.

### Question 1 - How many events were returned for the month of March 2022?

This question is fairly straightforward. On the Discover page, the field to select the date range is to the right of the search bar. The question is asking for us to find all events in just one month. We'll need to adjust both the start time and the end time for the range.

At the top of the calendar view, we see three options:`Absolute`, `Relative`, and `Now`. Select the `Absolute` option for both, and adjust the dates to include the entire month.

<img width="1084" height="606" alt="Screen Shot 2026-06-13 at 8 44 14 PM" src="https://github.com/user-attachments/assets/929ed28f-2ea6-40d3-9979-dbb99b185e8d" />

Click update. The number of events will be displayed prominently as a number of *hits*.

<img width="1084" height="566" alt="Screen Shot 2026-06-13 at 8 45 58 PM" src="https://github.com/user-attachments/assets/4423ae70-9439-40df-9f00-972881bfa04c" />

### Question 2 - What is the IP associated with the suspected user in the logs?

The easiest way to figure this out is to simply select the `source_ip` filter on the left-hand list of filters. Just 2 IP addresses are found in the records, and the IP associated with the user in question is the IP with just 2 hits (0.4%).

<img width="1087" height="648" alt="Screen Shot 2026-06-13 at 8 50 57 PM" src="https://github.com/user-attachments/assets/4c3a1948-bdce-4aec-9ed6-c8a64f6eb6e6" />

### Question 3 - The user’s machine used a legit windows binary to download a file from the C2 server. What is the name of the binary?

We need to add the user's IP address as a filter. Then, because we are interested in a downloaded file, we can add an additional filter: `method: GET`. Scroll down the list of filters, find `method`, and then click on the `+` icon next to `GET`.

<img width="1089" height="620" alt="Screen Shot 2026-06-13 at 8 57 40 PM" src="https://github.com/user-attachments/assets/89e16324-9e8a-4e0e-a9a9-9c810eff7f16" />

This narrows our search down to 1 hit. Click on the `>` next to the date of the log entry, which will reveal more information. In the expanded document, scroll down and look for the `user_agent` field. The name of the binary is found here.

( **BITSAdmin** is a built-in Windows command-line tool used to create, download, upload, and monitor Background Intelligent Transfer Service [BITS] jobs. Microsoft notes that while it's great for managing large file transfers, it is heavily monitored by security tools due to its ability to bypass standard download restrictions.)

<img width="1084" height="708" alt="Screen Shot 2026-06-13 at 9 01 51 PM" src="https://github.com/user-attachments/assets/9cf91152-6825-49bb-8a8a-ea46c028a47c" />

### Question 4 - The infected machine connected with a famous filesharing site in this period, which also acts as a C2 server used by the malware authors to communicate. What is the name of the filesharing site?

We can use the information found for the previous question. Looking through the expanded document further, we can see the `host` field, which will tell us what `bitsadmin` was connecting to.

The answer for this question is in the `host` field.

<img width="1077" height="565" alt="Screen Shot 2026-06-13 at 9 12 39 PM" src="https://github.com/user-attachments/assets/46c7e815-d2aa-4ff7-b7d7-d94120942140" />

### Question 5 - What is the full URL of the C2 to which the infected host is connected?

We've found the name of the filesharing site, and the specific web address can be constructed by adding one additional field in the expanded document.

Scroll through the document fields until you reach the `uri` field.  (a Uniform Resource Identifier [URI] includes two major types: URLs and URNs.) The value in this field just needs to be added to the website found in the previous question (the `host` field).

<img width="1083" height="679" alt="Screen Shot 2026-06-13 at 9 23 54 PM" src="https://github.com/user-attachments/assets/b860219d-5e57-4503-a7c4-a8b14d77aab7" />

### Question 6 - A file was accessed on the filesharing site. What is the name of the file accessed?

Once we have the full address, we can follow it!

The name of the file is found at the top of the page.

<img width="545" height="325" alt="Screen Shot 2026-06-13 at 9 26 52 PM" src="https://github.com/user-attachments/assets/e148e7e3-d0cc-4256-8599-e1f812fde725" />

### Question 7 - The file contains a secret code with the format THM{_____}.

The text of the file should be immediately viewable.

<img width="545" height="325" alt="Screen Shot 2026-06-13 at 9 26 52 PM" src="https://github.com/user-attachments/assets/e148e7e3-d0cc-4256-8599-e1f812fde725" />

~

And that's it!

This room serves as a great example to show just how much information can be extracted from just one source. It also serves as straightforward practice for combining search filters, and for learning what bits of info are associated with log fields.

Thanks for reading!
