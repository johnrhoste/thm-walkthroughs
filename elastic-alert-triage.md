# Alert Triage With Elastic

This tutorial covers the TryHackMe challenge *Alert Triage With Elastic*. In this room, we'll utilize Kibana (part of the ELK stack) to perform alert triage, conduct an initial investigation on suspicious activity, explore potential indicators of compromise (IoC), and gather evidence from various log sources.

Per TryHackMe, here are the objectives:

> * Use Kibana to analyze common security logs
> * Learn how to identify key indicators of compromise
> * Correlate events across multiple log sources
> * Uncover the breach through a series of SOC alerts

Link to room:
https://tryhackme.com/room/alerttriagewithelastic

## Task 1: Introduction

The room mentions a handful of recommended prerequisites:
* https://tryhackme.com/room/sysmon
* https://tryhackme.com/room/windowsloggingforsoc
* https://tryhackme.com/room/logsfundamentals
* https://tryhackme.com/room/investigatingwithelk101

Start the lab machine, wait a few minutes for Elastic to load, and then access the dashboard with the provided link in your preferred browser.

## Task 2: Scenario Briefing

In our scenario, some suspicious activity within the corporation's infrastructure has triggered multiple alerts.

We must determine if this activity is malicious, and reconstruct the attack sequence.

The first steps for this challenge are to set up our data view in Elastic.
1. Access the dashboard by clicking on the link provided.
2. Ensure that the correct Data View is selected on the left side of the dashboard. `Alert Triage With Elastic` should have a checkmark next to it.
3. Click on the calendar icon on the right-hand side, and select `Entire Data Range` to view all ingested logs.

<img width="440" height="445" alt="elastic-alert-triage-screenshot-1" src="https://github.com/user-attachments/assets/e31c3d97-4ae6-4493-a04f-c48a844788fb" /> <img width="50%" height="556" alt="elastic-alert-triage-screenshot-2" src="https://github.com/user-attachments/assets/9022c5a9-54f4-41a6-9a6d-1d254f41623f" />


### Question 1 - How many logs are available for analysis within the entire time range?

Once we've selected our data range, click on `Update`, which will then show us a total number of documents, which is the answer to the first question.

(Documents X,XXX)

<img width="945" height="661" alt="elastic-alert-triage-screenshot-3" src="https://github.com/user-attachments/assets/70e627d2-9ae0-44b1-beb9-b5b281d59ff3" />

### Question 2 - What is the field value for the  `client.ip`  in the  `weblogs`  index?

Add `_index:weblogs` to the filter / search box, and update the results.

On the left side, in the list of available fields, select `client.ip`, which reveals just a single value — this is what we're looking for.


<img width="999" height="586" alt="elastic-alert-triage-screenshot-4" src="https://github.com/user-attachments/assets/fa38e38c-2f32-4102-a596-cf5657500d2f" />


## Task 3: Investigating Web Attacks

We can now investigate the alerts.

Here's the information that we've been given by the SOC alert, showing web requests indicating a file upload.
1. The alert highlighted the IP address of `203.0.113.55`.
2. The IP made `POST` requests to the page `proxyLogon.ecp`, a possible attempt at exploitation.

We need to create a clean table to organize all of the available information and data. Adjust the parameters of the current query with the following changes:

1. Include the client IP address.
2. Focus on the `POST` requests.
3. Add `client.ip`, `user.agent`, `http.request.method`, `url.path`, and `http.response.status_code`.

The final query should look like this:

`_index:weblogs and client.ip:203.0.113.55 and http.request.method:POST`

Hit the `+` symbol next to each field from Step 3 above.

Our page should now look like this:


<img width="1674" height="663" alt="elastic-alert-triage-screenshot-5" src="https://github.com/user-attachments/assets/74544ef6-dc3a-491b-97af-a3e38af4814e" />


### Question 1 - How many  `POST`  requests did the IP address  `203.0.113.55`  make to  `proxyLogon.ecp`?

From the above search, we can see the total number of requests (Documents [ X ]). 

### Question 2 - Which `user.agent` paired with the IP address `203.0.113.55`  made the  `POST`  requests?

This information can also be found from the search. Glance at the `user.agent` field in the results to find the answer we're looking for. 

### Question 3 - How many logs contain the `cmd=` query parameter in the `url.path`  field?

This one is straightforward. Edit your query to search for `cmd=`:

`_index:weblogs and cmd=`

You can confirm this by inspecting the `url.path` field in the results; each should have `cmd=`. You'll notice that every result also has `errorEE` in the `url.path`.


<img width="1675" height="660" alt="elastic-alert-triage-screenshot-6" src="https://github.com/user-attachments/assets/db412dfc-bc98-4237-8441-89cdbe79e292" />


### Question 4 - Which command was run utilizing `errorEE.aspx`  on  `Jul 20, 2025 @ 04:45:50.000`?

Sort the documents by the `@timestamp` field, and then find the document with the correct time (04:45:50.000). 

The command can be found at the end of the `url.path`, or inside of the `message` field.


<img width="1672" height="825" alt="elastic-alert-triage-screenshot-7" src="https://github.com/user-attachments/assets/c398edb0-7a1c-492a-bf1d-f48adacabf6e" />


## Task 4: Uncovering Account Activity

We've identified suspicious network traffic, and there are certainly red flags that exist, but we need to now examine host-based evidence to determine the extent of an attack.

A SOC alert shows that an administrator has logged on outside of business hours. 

The next task is to confirm this logon event by investigating Event ID 4624.

A query has been provided for us. Enter the following into the search field:

`@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:4624 and host.name:winserv2019.some.corp and winlog.event_data.TargetUserName:Administrator`

We need to adjust the data fields. On the left side of the dashboard, we can remove all of the `Selected Fields` by selecting the `X` next to each one. Replace them with the following:

1.  `winlog.event_id`: Windows Event ID
2.  `host.name`: Target hostname on which the logon occurred
3.  `winlog.event_data.TargetUserName`: User account that logged in
4.  `winlog.logon.type`: How the user accessed the system (e.g., remotely via RDP)
5.  `winlog.event_data.IpAddress`: The source IP address of the client, a very important field

Our view should now look like this:


<img width="1677" height="543" alt="elastic-alert-triage-screenshot-8" src="https://github.com/user-attachments/assets/1915c688-63fe-4393-862c-0fd8c506c8af" />


### Question 1 - What is the  `winlog.record_id`  of the Administrator  `4624`  logon event?

Expand the document. We're looking for the `winlog.record_id` field, which should be on the 3rd page. 


<img width="1374" height="684" alt="elastic-alert-triage-screenshot-9" src="https://github.com/user-attachments/assets/a2f3a083-fe3a-492a-9b72-2139a23c8132" />


### Question 2 - What is the `process.pid`  of the Sysmon  `1`  event that occurred on  `Jul 20, 2025 @ 05:11:27.996`?

Next, we need to switch over to the Sysmon logs for further investigation. 

Adjust your query to search for Sysmon Event ID 1 (Process Creation) along with the admin username:

`@timestamp >= "2025-07-20T05:11:22" and winlog.event_id:1 and user.name:Administrator`'

36 documents should be shown.

Add the 1.  `user.name`, `process.parent.name` and `process.command_line`fields to the table.

Our screen should look like this:


<img width="1672" height="853" alt="elastic-alert-triage-screenshot-10" src="https://github.com/user-attachments/assets/6a06658f-1976-417c-bd28-82c4eff3e363" />


Finally, add the `process.pid` field to the table, and look for the document with the above event timestamp.

(The PID will be in the `process.pid` field.)


<img width="1667" height="535" alt="elastic-alert-triage-screenshot-11" src="https://github.com/user-attachments/assets/625eab43-a719-4e30-9b5e-62bc4dd5b338" />


### Question 3 - What is the `winlog.event_id`  for the new user account being created?

This answer can be found by a quick web search — the answer can be found on the Microsoft Learn website:


<img width="1657" height="665" alt="elastic-alert-triage-screenshot-12" src="https://github.com/user-attachments/assets/8b0d0a2d-70ee-4ed8-aae8-38489ed42ecc" />


### Question 4 - What is the name of the new user account?

The first step here is to create a new query using the event ID we found for the previous question:

`winlog.event_id : "4720"`

One document will be found.

We're given a hint: 

> Event ID 4720 and check out the winlog.event_data.TargetUserName field.

We'll expand the document and search for that specific field. The name of the new user account will be found in that field:


<img width="1671" height="702" alt="elastic-alert-triage-screenshot-13" src="https://github.com/user-attachments/assets/5e5f248a-80e0-4328-bc33-e27478a4b930" />


## Task 5: Exposing Command Execution

Our final task asks us to determine if an attacker is escalating their actions.

We're given a list of first steps to take:

> 1.  **Scope the alert**: Identify the child processes launched by  `cmd.exe`
>2.  **Confirm the origin**: Find out who launched `cmd.exe`  and why
>3.  **Check for privilege changes**: Look for commands like  `net`  used to add users to groups
>4.  **Correlate across log sources**: Use Sysmon and Windows Security logs to confirm the malicious behavior

### Question 1 - What command does the attacker use to add the new account to the "Remote Desktop Users" group?

First, we will create a query to find Sysmon events that include the parent process cmd.exe, and this will help you see what commands were executed. 

Use the following as the query:

`@timestamp >= "2025-07-20T05:13:15" and process.parent.name:cmd.exe and user.name:Administrator`


<img width="1673" height="620" alt="elastic-alert-triage-screenshot-14" src="https://github.com/user-attachments/assets/c255c5a7-2c85-4a36-9862-1b75a035f539" />


We'll make a table with the following fields: `process.command_line`, `process.name`, and `process.parent.name`.

In the `process.command_line` field, we'll find the full command for adding the new account.


<img width="1088" height="625" alt="elastic-alert-triage-screenshot-15" src="https://github.com/user-attachments/assets/d428c425-a9a6-417e-9496-1f6f49bc26ff" />


### Question 2 - What is the `winlog.record_id`  of the  `4732`  Security event when the attacker adds the user to the Administrator group?

Use this query:

`@timestamp >= "2025-07-20T05:13:15" and (winlog.event_id:4732 or process.parent.name:cmd.exe)`

Look for the `message` that shows a user being added to the Administrator group.


<img width="1368" height="763" alt="elastic-alert-triage-screenshot-16" src="https://github.com/user-attachments/assets/20b39f52-a773-49c8-b791-be211d65df1a" />


### Question 3 - What PowerShell command did the attacker run on  `Jul 20, 2025 @ 05:16:14.628`?

Utilized this query:

`@timestamp >= "2025-07-20T05:13:15" and event.module:powershell and event.code:4104`

Add the field `powershell.file.script_block_text` as a column to show the commands in plaintext, and then sort by `Old-New`.

Find the entry with the relevant time, and then check the command in the `powershell.file.script_block_text` field.


<img width="1674" height="757" alt="Screen Shot 2026-06-14 at 6 46 44 PM" src="https://github.com/user-attachments/assets/eadbb061-5ecb-413b-a20b-bce4e7d597b1" />


### Question 4 - What is the name of the archive that the attacker creates using the  `Rar.exe`  executable?

This final question is extremely easy. All we need to do is add `rar.exe` to the query box. That's it! 

The answer will show up in the `process.command_line` field, but we can also find it in the `message` field:


<img width="1371" height="597" alt="elastic-alert-triage-screenshot-18" src="https://github.com/user-attachments/assets/5a8cfc87-94c7-45a4-8ff5-569fb685497a" />



## Conclusion

In this challenge, we explored the Elastic / Kibana interface, searched and filtered for both web and Windows logs, found some critical indicators of compromise, and correlated events across logs.

Thanks for reading.
