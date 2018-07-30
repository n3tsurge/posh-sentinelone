**NOTE: This project is being archive.  The new module version can be found here https://github.com/zeroonesec/posh-sentinelone2.0**

# Posh-SentinelOne

A Powershell Module for managing Sentinel One allowing for easier integration into Powershell scripts and automation routines.

# Disclaimer

This module is provided as is without warranty.  The author does not work for or represent SentinelOne in any capacity.  The author is not responsible for damage to your system or SentinelOne implementation if you use this module.


# Upcoming

- Hunt threats (Sentinel One Deep Visibility)
- Support for different proxy credentials
- More in-depth documentation and helper XMl files

# Install

`Import-Module .\Posh-SentinelOne.psm1 -ArgumentList <tenant>,<proxy=optional>`

> This module is self-updating, it will automatically check the git repository for a new version and update it.  

To disable the self update functionality, before importing the module do the following

1. Open Posh-SentinelOne.psd1
2. Locate the following line of code

```
# Script files (.ps1) that are run in the caller's environment prior to importing this module.
ScriptsToProcess = @("SelfUpdate.ps1")
```
3. Change the code to this

```
# Script files (.ps1) that are run in the caller's environment prior to importing this module.
#ScriptsToProcess = @("SelfUpdate.ps1")
```

# Commands

Command | Description
--- | ---
Get-S1Group | Retrieves group information from SentinelOne
Set-S1APIKey | Stores a SentinelOne API Key in encrypted format on the machine
Read-S1APIKey | Reads the SentinelOne key for use when calling the API
New-S1Hash | Creates a new hash in SentinelOne
Get-S1AgentProcesses | Retrieves the running processes on an agent
Get-S1AgentApplications | Retrives the installed applications on an agent
Get-S1AgentPassphrase | Retrieves the passphrase for an agent
Invoke-S1AgentScan | Starts a full disk scan on an agent
Stop-S1AgentScan | Stops a full disk scan on an agent
Get-S1Agent | Retrieves information on a single agent or multiple agents
Get-S1Agents | Iterates through all the agents and pulls them into a collection
Get-S1Threat | Retrives information on a threat
Set-S1ThreatResolved | Resolves a threat
Invoke-S1IsolateAgent | Isolates an agent
Invoke-S1ConnectAgent | Reconnects an agent to the network
Get-S1ThreatForensics | Retrieves the detailed forensic information on a threat
New-S1User | Creates a new user in the SentinelOne Console

# Command Usage

## Global Parameters
All functions support the following parameters

Parameter | Description
--- | ---
**ApiKey** | The SentinelOne API Key to use
**Proxy**| The proxy to use
**ProxyUseDefaultCredentials** | Whether to use the credentials of the user running the command for proxy authentication or not

### Get-S1Agent

**Parameters**

Parameter | Description
--- | ---
**Query** | The query used to search for computers
**AgentID** | The id for the agent. **NOT** the UUID
**Limit** | How many results to return
**Brief** | Display only summary information about the agents returned (Default: Agent Name, Last Logged On User)

```powershell
$ Get-S1Agent -Query $env:COMPUTERNAME -ProxyUseDefaultCredentials


network_status           : connected
is_pending_uninstall     : False
last_active_date         : 2018-02-13T14:28:44.266000Z
scan_status              : @{status=2; aborted_at=2018-02-12T13:51:38.651000Z; started_at=2018-02-12T13:50:38.527000Z; finished_at=2017-12-15T17:05:44.003000Z}
registered_at            : 2017-12-15T16:21:28.496000Z
last_logged_in_user_name : REDACTED
id                       : 5a33f68899835405c693024a
uuid                     : 59ec98933a29aaa697ceeafe83384927612009c8
encrypted_applications   : False
hardware_information     : @{total_memory=16268; cpu_count=4; cpu_id=Intel(R) Core(TM) i5-6300U CPU @ 2.40GHz; machine_type=laptop; model_name=Dell Inc. - Latitude 7480; core_count=4}
software_information     : @{os_start_time=2018-02-13T13:15:47Z; os_revision=No ServicePack Installed; os_type=2; os_name=Windows 10; os_arch=64 bit}
is_uninstalled           : False
users                    : {@{login_time=2018-02-13T13:17:15.344+00:00; name=REDACTED; sid=REDACTED}}
is_active                : True
is_decommissioned        : False
meta_data                : @{created_at=2017-12-15T16:21:28.496000Z; updated_at=2018-02-13T13:16:15.581000Z}
configuration            : @{mitigation_mode=protect; auto_mitigation_actions=System.Object[]; mitigation_mode_suspicious=protect; learning_mode=False; research_data=researchData.collectAndSend}
user_actions_needed      : 1
assets                   : {@{version=54; name=static}, @{version=54; name=weights}, @{version=54; name=logicconfigs}}
external_ip              : 198.199.134.100
is_up_to_date            : True
group_ip                 : 198.199.134.x
network_information      : @{domain=REDACTED; interfaces=System.Object[]; computer_name=REDACTED}
threat_count             : 0
group_id                 : 59bfe73c9983545c5550d654
agent_version            : 2.5.1.54
```

### Get-S1Group

```powershell
$ Get-S1Group -GroupID 59301c6bf0ed60433d3abe04 -ProxyUseDefaultCredentials

is_default : True
source     : Default group
rank       :
meta_data  : @{created_at=2017-06-01T13:53:47.197000Z; updated_at=2017-12-20T20:48:34.862000Z}
user_id    :
name       : Deploy
filter_id  :
id         : 59301c6bf0ed60433d3abe04
ad_query   :
policy_id  : 59bfe73c9983545c5550d653
```
