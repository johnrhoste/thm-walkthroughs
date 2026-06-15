# Alert Triage With Elastic

This tutorial covers the TryHackMe challenge *Alert Triage With Splunk*. In this room, we'll utilize Splunk to investigate suspicious activity from multiple assets.

Here are the objectives:

>-   Learn how to properly investigate alerts in a  SOC  environment.
>-   Understand how to investigate brute-force attacks on  Linux  systems.
>-   Discover the  persistence  mechanism on Windows systems.
>-   Analyse a web shell on a vulnerable web server.
>-   Learn how to investigate alerts for three given scenarios using  Splunk.

Link to room:
https://tryhackme.com/room/alerttriagewithsplunk

# Task 1: Introduction

The room mentions a handful of recommended prerequisites:
-   [Introduction to  SIEM](https://tryhackme.com/room/introtosiem)
-   [Splunk: Basics](https://tryhackme.com/room/splunk101)
-   [Windows Logging Capabilities](https://tryhackme.com/room/windowsloggingforsoc)
-   [Log Analysis with  SIEM](https://tryhackme.com/room/loganalysiswithsiem)
-   [Sysmon](https://tryhackme.com/r/room/sysmon)

Start the lab machine. The Splunk interface may take ~5 minutes to properly load.

**Important:** Ensure that you set the date range to `All Time` in the list of range presets.


<img width="845" height="354" alt="Screen Shot 2026-06-15 at 11 21 18 AM" src="https://github.com/user-attachments/assets/9757f76c-cbe2-4207-b8c3-9de67a627781" />


# Task 2: Initial Access Alert

Here's the information that we are provided about the alert we've received:

> -   **Alert Name:**  Brute Force Activity Detection
>-   **Time:**  17/09/2025 9:00:21 AM
>-   **Target Host:**  tryhackme-2404
>-   **Source IP:**  10.10.242.248

The index for this task is `linux-alert`.

In the query box, create an initial query with the following (and make sure that the date range is set to `All Time`):

`index=linux-alert`

Let's first focus on the alert data.

The Source IP is a local IP address. This gives us our first bit of major information, because if this alert is truly coming from an attacker, they have already found a way into, and have accessed, the organization's network.

The timestamp of this alert shows that it was within normal business hours, so that doesn't provide any more evidence of an attack.

Let's move over to Splunk to look for more information.

In the query box, change the query to the following:

`index="linux-alert" sourcetype="linux_secure" 10.10.242.248  
| search "Accepted password for" OR "Failed password for" OR "Invalid user"  
| sort + _time`

This will provide results for successful and failed login attempts, in addition to events connected to invalid users (which would be a clue that an attack is attempting to enumerate user accounts).

Using the above search, we get 543 events associated with the 10.10.242.248 address. Note that we are seeing a number of results with `invalid user`... but we need to investigate further.


<img width="1672" height="769" alt="Screen Shot 2026-06-15 at 11 37 47 AM" src="https://github.com/user-attachments/assets/99190a41-5154-44ba-9526-17768b07dad4" />


We're going to run another search to determine the number of login attempts made for each user:

`index="linux-alert" sourcetype="linux_secure" 10.10.242.248  
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"  
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"  
| eval process="sshd"  
| stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username`

Here are the results:


<img width="1675" height="562" alt="Screen Shot 2026-06-15 at 11 50 41 AM" src="https://github.com/user-attachments/assets/459aa939-f3f6-45e5-aa30-29abea5f34aa" />


David, Sarah and Emma have a handful of failed logins, but that's nothing out of the ordinary. However, user `john.smith` shows an extremely high number of login attempts — 503.

This is a clear indication of a brute force attempt.

We need to determine if the attack was successful. The following query will give us information on whether the attacker was able to gain access:

`index="linux-alert" sourcetype="linux_secure" 10.10.242.248  
| rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"  
| rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"  
| eval process="sshd"  
| stats count values(action) values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username`

All login attempts on the other 3 users failed. User `john.smith` had 500 failed attempts and 3 accepted attempts.

Therefore, we can confirm that the brute force attack **was successful.** The attacker was able to access `tryhackme-2404` (the host). 

This will be classified as a **True Positive.** If this were a real scenario, our role as an L1 analyst would be complete, and we would escalate this to an L2 analyst for additional investigation.

## Question 1 - How many failed login attempts were made on the user john.smith?

Remove the `Accepted` option from the `action` filter, which will leave us the number of failed attempts for john.smith.


<img width="1035" height="552" alt="Screen Shot 2026-06-15 at 12 04 31 PM" src="https://github.com/user-attachments/assets/78a746f9-7748-44ea-a8d0-0f63286fae1b" />


## Question 2 - What was the duration of the brute force attack in minutes?

For this, we need the `src_ip` filter, combined with `action=failure`. We'll focus this query on the user `john.smith`.

Here's the full query to visualize the timeline:

1src_ip=10.10.242.248 action=failure user=john.smith
| table _time, user, action1


<img width="1661" height="668" alt="Screen Shot 2026-06-15 at 12 10 37 PM" src="https://github.com/user-attachments/assets/af76a59a-00d8-43b3-984c-0f38034b33ff" />


By sorting the data by the timestamp, we'll see that the first record is at at `09:01:50.282`. Reversing the sorting shows the last record is at `09:06:35.029`.

The brute force attack was roughly 5 minutes.


## Question 3 - What username was the attacker able to privilege escalate to?

Let's start here by searching for all logs related to the user `john.smith`, not including all of the brute force attempts.

Let's make a new query that excludes the `faliure` action:

`user=john.smith action!=failure`


<img width="1664" height="666" alt="Screen Shot 2026-06-15 at 12 19 57 PM" src="https://github.com/user-attachments/assets/f0cf696e-19e8-40e5-a2c4-0d4486283e9d" />


With these results, we see a number of `session opened` messages for user `john.smith` by `john.smith`... can we find sessions opened by `john.smith` **_for_** other users?

Let's check. Let's remove `user=john.smith` from our query and simply search for `john.smith` anywhere.

Here's the revised query:

`john.smith action!=failure`

This adds 3 more results, and it reveals a pair of extremely concerning events:


<img width="1661" height="771" alt="Screen Shot 2026-06-15 at 12 23 57 PM" src="https://github.com/user-attachments/assets/bd122050-4c56-4eeb-85e7-1764b8ae016d" />


A session was opened for user `root`.

## Question 4 - What is the name of the user account created by the attacker for persistence?

We'll make an assumption that the new user account was created with `root`.

We'll create a quick query with the hostname, along with `root`.

Here's the query:

`tryhackme-2404 root`

<img width="1661" height="829" alt="Screen Shot 2026-06-15 at 12 29 27 PM" src="https://github.com/user-attachments/assets/ae41f5f8-1727-4487-a915-bc34580906d5" />


Searching through the results, we see `COMMAND=/usr/sbin/adduser`. The name of the user account that was created is following that — `system-utm`.

I'm unsure if there's any significance to that name, but it looks normal enough to pass off as a plausible service / system account to the casual user.

# Task 3: Persistence Alert

We're now working with a new alert — one that indicates a suspicious scheduled task. Here are the details:

>-   **Alert Name:**  Potential Task Scheduler  Persistence  Identified
>-   **Time:**  30/08/2025 10:06:07 AM
>-   **Host:**  WIN-H015
>-   **User:**  oliver.thompson
>-   **Task Name:**  AssessmentTaskOne

The Splunk index for this task is `win-alert`. The query we'll use is:

`index=win-alert`

However, before we jump into Splunk, we need to look through the alert details. Specifically, we need to look at the `Host` and and determine what kind of host this is.

Servers commonly have these prefixes:
* SRV-
* WEB-
* MSQL-

Individual workstations may have prefixes such as WIN- or HOST-. In our scenario, we can assume that `WIN-H015` is therefore a workstation for user Oliver Thompson.

Let's shift to Splunk for analysis.

First, we need to know that event ID `4698` is used for the creation of a scheduled task. We'll include that in our query, along with the task name from the original alert details.

Here's the full query we'll use:

`index="win-alert" EventCode=4698 AssessmentTaskOne  
| table _time EventCode user_name host Task_Name Message`


<img width="1660" height="722" alt="Screen Shot 2026-06-15 at 12 56 22 PM" src="https://github.com/user-attachments/assets/f53c6aab-2dac-4d7c-ab48-f840df543996" />


Just 1 event is shown related to this activity.

We'll need to review the `message` to determine what the task does.

First, glance at the `<Triggers>` section. This reveals the start time for the task. The `<DaysInterval>` shows `1`, meaning that it is configured to run every day at the same time. Considering that we're looking at a user's workstation, this is a red flag.

Scroll down to the `<exec>` and `<Principals>` sections.

The `<Exec>` section reveals that the task uses `certutil` to download `rv.exe` from a suspicious domain — `tryhotme`. It will place this file into the Temp folder, renaming itself to a suspiciously-named `DataCollector.exe`. Powershell will then be used to launch the file.

We can consider this all to be indicators of an attacker attempting to maintain persistence within the system.

Therefore, this alert must be classified as a True Positive, and it must be escalated to an L2 analyst.

## Question 1 - What is the ProcessId of the process that created this malicious task?

In the `message` field of the activity record, we'll find the ProcessID in `ClientProcessID`.


<img width="457" height="288" alt="Screen Shot 2026-06-15 at 1 07 21 PM" src="https://github.com/user-attachments/assets/12b021dd-d35e-443e-b23c-eb1feeb15e80" />


## Question 2 - What is the name of the parent process for the process that created this malicious task?

This one only required a very quick search. I modified my query to simply look for `rv.exe`. Here's the query:

`index="win-alert" rv.exe`

We'll take a closer look at the `Sysmon` log record. I realized that we could've looked here for the `ProcessId`. Near the bottom of this entry, though, is what we're looking for: `ParentCommandLine`, which shows the parent process: `C:\Windows\system32\cmd.exe`.


<img width="797" height="534" alt="Screen Shot 2026-06-15 at 1 17 43 PM" src="https://github.com/user-attachments/assets/88c37b01-7ac8-45c3-adb2-0c06177e0d42" />


## Question 3 - Which local group did the attacker enumerate during discovery?

We'll make a new query with our host name, `WIN-H015`, as well as `net.exe`.

If an attacker wants to enumerate users easily, they are likely to use `net.exe`.

<img width="1661" height="773" alt="Screen Shot 2026-06-15 at 1 21 23 PM" src="https://github.com/user-attachments/assets/aeeac4da-3dcf-41e8-9d7b-e9e2db51e4aa" />


In the `ParentCommandLine`, we'll find the specific local group.


