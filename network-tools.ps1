<#
.SYNOPSIS
    Network Tools GUI - Cross-Platform PowerShell Network & Firewall Toolkit

.DESCRIPTION
    A PowerShell-based graphical interface for common host, local, and firewall network diagnostics and management.
    Features include ping, traceroute, nmap, port checks, DNS tools, TCP/UDP connections, ARP, firewall management, and more.
    Suitable for IT admins and power users on Windows and Linux.

.AUTHOR
    Alan O'Brien <aobrien@ehs.com>

.VERSION
    1.0

.LICENSE
    GPL-3.0 license
.LINK
    https://www.gnu.org/licenses/gpl-3.0.en.html

.REQUIREMENTS
    - PowerShell 5.1+ (Windows) or PowerShell 7+ (Linux/macOS)
    - System.Windows.Forms (comes with Windows PowerShell; for Linux, requires PowerShell 7+ and X11)
    - Admin rights for some features (firewall, ARP, etc.)
    - Optional: nmap, nc/netcat, ufw/firewalld

.USAGE
    # Windows:
    powershell -ExecutionPolicy Bypass -File .\network-gui.ps1

    # Linux (with PowerShell 7+):
    pwsh ./network-gui-linux.ps1

.NOTES
    This script is provided as-is, without warranty of any kind. Test in non-production environments first.
    Contributions and improvements are welcome!

.LINK
    https://github.com/dreadnought31/Network-Tools
#>
<#
.SYNOPSIS
    Network Tools GUI - Cross-Platform PowerShell Network & Firewall Toolkit

.DESCRIPTION
    A PowerShell-based graphical interface for common host, local, and firewall network diagnostics and management.
    Features include ping, traceroute, nmap, port checks, DNS tools, TCP/UDP connections, ARP, firewall management, and more.
    Suitable for IT admins and power users on Windows and Linux.

.AUTHOR
    Alan O'Brien <aobrien@ehs.com>

.VERSION
    1.0

.LICENSE
    GPL-3.0 license
.LINK
    https://www.gnu.org/licenses/gpl-3.0.en.html

.REQUIREMENTS
    - PowerShell 5.1+ (Windows) or PowerShell 7+ (Linux/macOS)
    - System.Windows.Forms (comes with Windows PowerShell; for Linux, requires PowerShell 7+ and X11)
    - Admin rights for some features (firewall, ARP, etc.)
    - Optional: nmap, nc/netcat, ufw/firewalld

.USAGE
    # Windows:
    powershell -ExecutionPolicy Bypass -File .\network-gui.ps1

    # Linux (with PowerShell 7+):
    pwsh ./network-gui-linux.ps1

.NOTES
    This script is provided as-is, without warranty of any kind. Test in non-production environments first.
    Contributions and improvements are welcome!

.LINK
    https://github.com/dreadnought31/Network-Tools
#>
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory)]
        [string]$Command,
        [string[]]$Arguments = @()
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Command
    $psi.Arguments = ($Arguments -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    try {
        $process.Start() | Out-Null
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -eq 0) {
            return $stdout
        } else {
            return "Error running command:`n$stderr"
        }
    } catch {
        return "Exception occurred: $($_.Exception.Message)"
    } finally {
        $process.Close()
    }
}

# Main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Network Tools"
$form.Size = New-Object System.Drawing.Size(950, 700)
$form.StartPosition = "CenterScreen"

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Size = New-Object System.Drawing.Size(900, 650)
$tabs.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($tabs)

# ---- Tab 1: Host Tools ----
$tabHost = New-Object System.Windows.Forms.TabPage
$tabHost.Text = "Host Tools"
$tabs.Controls.Add($tabHost)

$labelHost = New-Object System.Windows.Forms.Label
$labelHost.Text = "Target Host/IP:"
$labelHost.Location = New-Object System.Drawing.Point(20, 20)
$labelHost.Size = New-Object System.Drawing.Size(120, 20)
$tabHost.Controls.Add($labelHost)

$textHost = New-Object System.Windows.Forms.TextBox
$textHost.Location = New-Object System.Drawing.Point(150, 20)
$textHost.Size = New-Object System.Drawing.Size(200, 20)
$tabHost.Controls.Add($textHost)

$labelPort = New-Object System.Windows.Forms.Label
$labelPort.Text = "Nmap/Test Port(s) (optional):"
$labelPort.Location = New-Object System.Drawing.Point(370, 20)
$labelPort.Size = New-Object System.Drawing.Size(170, 20)
$tabHost.Controls.Add($labelPort)

$textPort = New-Object System.Windows.Forms.TextBox
$textPort.Location = New-Object System.Drawing.Point(540, 20)
$textPort.Size = New-Object System.Drawing.Size(100, 20)
$tabHost.Controls.Add($textPort)

$resultHost = New-Object System.Windows.Forms.TextBox
$resultHost.Multiline = $true
$resultHost.ScrollBars = "Vertical"
$resultHost.Location = New-Object System.Drawing.Point(20, 170)
$resultHost.Size = New-Object System.Drawing.Size(820, 350)
$resultHost.Font = New-Object System.Drawing.Font("Consolas", 10)
$tabHost.Controls.Add($resultHost)

# Ping
$pingBtn = New-Object System.Windows.Forms.Button
$pingBtn.Text = "Ping"
$pingBtn.Location = New-Object System.Drawing.Point(20, 60)
$pingBtn.Size = New-Object System.Drawing.Size(100, 40)
$pingBtn.Add_Click({
    $target = $textHost.Text.Trim()
    if ($target) {
        $resultHost.Text = "Running ping $target ..."
        $output = Invoke-ExternalCommand -Command "ping.exe" -Arguments @($target)
        $resultHost.Text = $output
    } else {
        $resultHost.Text = "Please enter a target host or IP."
    }
})
$tabHost.Controls.Add($pingBtn)

# Tracert
$tracertBtn = New-Object System.Windows.Forms.Button
$tracertBtn.Text = "Tracert"
$tracertBtn.Location = New-Object System.Drawing.Point(140, 60)
$tracertBtn.Size = New-Object System.Drawing.Size(100, 40)
$tracertBtn.Add_Click({
    $target = $textHost.Text.Trim()
    if ($target) {
        $resultHost.Text = "Running tracert $target ..."
        $output = Invoke-ExternalCommand -Command "tracert.exe" -Arguments @($target)
        $resultHost.Text = $output
    } else {
        $resultHost.Text = "Please enter a target host or IP."
    }
})
$tabHost.Controls.Add($tracertBtn)

# Nmap
$nmapBtn = New-Object System.Windows.Forms.Button
$nmapBtn.Text = "Nmap"
$nmapBtn.Location = New-Object System.Drawing.Point(260, 60)
$nmapBtn.Size = New-Object System.Drawing.Size(100, 40)
$nmapBtn.Add_Click({
    $target = $textHost.Text.Trim()
    $ports = $textPort.Text.Trim()
    if ($target) {
        $resultHost.Text = "Running nmap $target" + ($(if ($ports) { " on port(s) $ports..." } else { "..." }))
        $nmapPath = "nmap.exe"
        if ($ports) {
            $output = Invoke-ExternalCommand -Command $nmapPath -Arguments @("-p", $ports, $target)
        } else {
            $output = Invoke-ExternalCommand -Command $nmapPath -Arguments @($target)
        }
        $resultHost.Text = $output
    } else {
        $resultHost.Text = "Please enter a target host or IP."
    }
})
$tabHost.Controls.Add($nmapBtn)

# Test-NetConnection
$testNetBtn = New-Object System.Windows.Forms.Button
$testNetBtn.Text = "Test-NetConnection"
$testNetBtn.Location = New-Object System.Drawing.Point(380, 60)
$testNetBtn.Size = New-Object System.Drawing.Size(150, 40)
$testNetBtn.Add_Click({
    $target = $textHost.Text.Trim()
    $ports = $textPort.Text.Trim()
    if ($target) {
        if ($ports) {
            try {
                $output = Test-NetConnection -ComputerName $target -Port ([int]$ports) | Out-String
                $resultHost.Text = $output
            } catch {
                $resultHost.Text = "Error: $($_.Exception.Message)"
            }
        } else {
            try {
                $output = Test-NetConnection -ComputerName $target | Out-String
                $resultHost.Text = $output
            } catch {
                $resultHost.Text = "Error: $($_.Exception.Message)"
            }
        }
    } else {
        $resultHost.Text = "Please enter a target host or IP."
    }
})
$tabHost.Controls.Add($testNetBtn)

# Nslookup
$nslookupBtn = New-Object System.Windows.Forms.Button
$nslookupBtn.Text = "Nslookup"
$nslookupBtn.Location = New-Object System.Drawing.Point(550, 60)
$nslookupBtn.Size = New-Object System.Drawing.Size(100, 40)
$nslookupBtn.Add_Click({
    $target = $textHost.Text.Trim()
    if ($target) {
        $resultHost.Text = "Running nslookup $target ..."
        $output = Invoke-ExternalCommand -Command "nslookup.exe" -Arguments @($target)
        $resultHost.Text = $output
    } else {
        $resultHost.Text = "Please enter a target host or IP."
    }
})
$tabHost.Controls.Add($nslookupBtn)

# ---- Tab 2: Local Tools ----
$tabLocal = New-Object System.Windows.Forms.TabPage
$tabLocal.Text = "Local Tools"
$tabs.Controls.Add($tabLocal)

$resultLocal = New-Object System.Windows.Forms.TextBox
$resultLocal.Multiline = $true
$resultLocal.ScrollBars = "Vertical"
$resultLocal.Location = New-Object System.Drawing.Point(20, 220)
$resultLocal.Size = New-Object System.Drawing.Size(820, 300)
$resultLocal.Font = New-Object System.Drawing.Font("Consolas", 10)
$tabLocal.Controls.Add($resultLocal)

$checkNetBtn = New-Object System.Windows.Forms.Button
$checkNetBtn.Text = "Check Network"
$checkNetBtn.Location = New-Object System.Drawing.Point(20, 20)
$checkNetBtn.Size = New-Object System.Drawing.Size(160, 35)
$checkNetBtn.Add_Click({
    $resultLocal.Text = "Checking network interfaces ..."
    $output = Invoke-ExternalCommand -Command "netsh.exe" -Arguments @("interface", "ipv4", "show", "interfaces")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($checkNetBtn)

$routesBtn = New-Object System.Windows.Forms.Button
$routesBtn.Text = "Show Routes"
$routesBtn.Location = New-Object System.Drawing.Point(200, 20)
$routesBtn.Size = New-Object System.Drawing.Size(120, 35)
$routesBtn.Add_Click({
    $resultLocal.Text = "Showing routes ..."
    $output = Invoke-ExternalCommand -Command "route.exe" -Arguments @("print")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($routesBtn)

$netCatBtn = New-Object System.Windows.Forms.Button
$netCatBtn.Text = "Network Category"
$netCatBtn.Location = New-Object System.Drawing.Point(340, 20)
$netCatBtn.Size = New-Object System.Drawing.Size(160, 35)
$netCatBtn.Add_Click({
    $resultLocal.Text = "Getting network profile ..."
    try {
        $output = Get-NetConnectionProfile | Out-String
        $resultLocal.Text = $output
    } catch {
        $resultLocal.Text = "Error: $($_.Exception.Message)"
    }
})
$tabLocal.Controls.Add($netCatBtn)

$getLogsBtn = New-Object System.Windows.Forms.Button
$getLogsBtn.Text = "Get Logs"
$getLogsBtn.Location = New-Object System.Drawing.Point(520, 20)
$getLogsBtn.Size = New-Object System.Drawing.Size(100, 35)
$getLogsBtn.Add_Click({
    $resultLocal.Text = "Getting last 20 System event logs ..."
    try {
        $output = Get-EventLog -LogName System -Newest 20 | Out-String
        $resultLocal.Text = $output
    } catch {
        $resultLocal.Text = "Error: $($_.Exception.Message)"
    }
})
$tabLocal.Controls.Add($getLogsBtn)

$getIPCfgBtn = New-Object System.Windows.Forms.Button
$getIPCfgBtn.Text = "Get IP Config"
$getIPCfgBtn.Location = New-Object System.Drawing.Point(640, 20)
$getIPCfgBtn.Size = New-Object System.Drawing.Size(120, 35)
$getIPCfgBtn.Add_Click({
    $resultLocal.Text = "Getting IP configuration ..."
    $output = Invoke-ExternalCommand -Command "ipconfig.exe" -Arguments @("/all")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($getIPCfgBtn)

$dnsCacheBtn = New-Object System.Windows.Forms.Button
$dnsCacheBtn.Text = "Show DNS Cache"
$dnsCacheBtn.Location = New-Object System.Drawing.Point(20, 70)
$dnsCacheBtn.Size = New-Object System.Drawing.Size(160, 35)
$dnsCacheBtn.Add_Click({
    $resultLocal.Text = "Showing DNS cache ..."
    $output = Invoke-ExternalCommand -Command "ipconfig.exe" -Arguments @("/displaydns")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($dnsCacheBtn)

$flushDNSBtn = New-Object System.Windows.Forms.Button
$flushDNSBtn.Text = "Flush DNS"
$flushDNSBtn.Location = New-Object System.Drawing.Point(200, 70)
$flushDNSBtn.Size = New-Object System.Drawing.Size(120, 35)
$flushDNSBtn.Add_Click({
    $resultLocal.Text = "Flushing DNS cache ..."
    $output = Invoke-ExternalCommand -Command "ipconfig.exe" -Arguments @("/flushdns")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($flushDNSBtn)

# RELEASE IP
$releaseIPBtn = New-Object System.Windows.Forms.Button
$releaseIPBtn.Text = "Release IP"
$releaseIPBtn.Location = New-Object System.Drawing.Point(340, 70)
$releaseIPBtn.Size = New-Object System.Drawing.Size(120, 35)
$releaseIPBtn.Add_Click({
    $resultLocal.Text = "Releasing IP addresses ..."
    $output = Invoke-ExternalCommand -Command "ipconfig.exe" -Arguments @("/release")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($releaseIPBtn)

# RENEW IP
$renewIPBtn = New-Object System.Windows.Forms.Button
$renewIPBtn.Text = "Renew IP"
$renewIPBtn.Location = New-Object System.Drawing.Point(480, 70)
$renewIPBtn.Size = New-Object System.Drawing.Size(120, 35)
$renewIPBtn.Add_Click({
    $resultLocal.Text = "Renewing IP addresses ..."
    $output = Invoke-ExternalCommand -Command "ipconfig.exe" -Arguments @("/renew")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($renewIPBtn)

$netSharesBtn = New-Object System.Windows.Forms.Button
$netSharesBtn.Text = "Show Net Shares"
$netSharesBtn.Location = New-Object System.Drawing.Point(640, 70)
$netSharesBtn.Size = New-Object System.Drawing.Size(100, 35)
$netSharesBtn.Add_Click({
    $resultLocal.Text = "Listing network shares ..."
    $output = Invoke-ExternalCommand -Command "net.exe" -Arguments @("share")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($netSharesBtn)

$portUsageBtn = New-Object System.Windows.Forms.Button
$portUsageBtn.Text = "Check Port Usage"
$portUsageBtn.Location = New-Object System.Drawing.Point(20, 120)
$portUsageBtn.Size = New-Object System.Drawing.Size(120, 35)
$portUsageBtn.Add_Click({
    $resultLocal.Text = "Checking port usage ..."
    $output = Invoke-ExternalCommand -Command "netstat.exe" -Arguments @("-ano")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($portUsageBtn)

$tcpConnBtn = New-Object System.Windows.Forms.Button
$tcpConnBtn.Text = "List TCP Connections"
$tcpConnBtn.Location = New-Object System.Drawing.Point(160, 120)
$tcpConnBtn.Size = New-Object System.Drawing.Size(160, 35)
$tcpConnBtn.Add_Click({
    $resultLocal.Text = "Listing TCP connections ..."
    $output = Invoke-ExternalCommand -Command "netstat.exe" -Arguments @("-n")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($tcpConnBtn)

$arpBtn = New-Object System.Windows.Forms.Button
$arpBtn.Text = "ARP -a"
$arpBtn.Location = New-Object System.Drawing.Point(340, 120)
$arpBtn.Size = New-Object System.Drawing.Size(100, 35)
$arpBtn.Add_Click({
    $resultLocal.Text = "Running arp -a ..."
    $output = Invoke-ExternalCommand -Command "arp.exe" -Arguments @("-a")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($arpBtn)

# ---- Tab 3: Firewall ----
$tabFW = New-Object System.Windows.Forms.TabPage
$tabFW.Text = "Firewall"
$tabs.Controls.Add($tabFW)

$resultFW = New-Object System.Windows.Forms.TextBox
$resultFW.Multiline = $true
$resultFW.ScrollBars = "Vertical"
$resultFW.Location = New-Object System.Drawing.Point(20, 370)
$resultFW.Size = New-Object System.Drawing.Size(820, 150)
$resultFW.Font = New-Object System.Drawing.Font("Consolas", 10)
$tabFW.Controls.Add($resultFW)

function Add-FWPSButton {
    param($tab, $text, $locX, $locY, $scriptblock)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Location = New-Object System.Drawing.Point($locX, $locY)
    $btn.Size = New-Object System.Drawing.Size(270, 35)
    $btn.Add_Click($scriptblock)
    $tab.Controls.Add($btn)
}

Add-FWPSButton $tabFW "Check Firewall Status (All profiles)" 20 20 {
    try {
        $output = Get-NetFirewallProfile | Format-Table Name, Enabled | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "View Current Firewall Settings (Detailed)" 320 20 {
    try {
        $output = Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Enable Firewall (All profiles)" 20 70 {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        $resultFW.Text = "Firewall enabled for all profiles."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Disable Firewall (All profiles)" 320 70 {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        $resultFW.Text = "Firewall disabled for all profiles."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "List All Firewall Rules" 20 120 {
    try {
        $output = Get-NetFirewallRule | Select-Object DisplayName, Enabled, Action, Direction | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "List Firewall Rules by Port" 320 120 {
    try {
        $output = Get-NetFirewallPortFilter | Select-Object LocalPort, Protocol, @{N='RuleName';E={$_.InstanceID}} | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Reset Firewall Settings to Default" 20 170 {
    try {
        (New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()
        $resultFW.Text = "Firewall settings reset to default."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Export Firewall Rules" 320 170 {
    try {
        if (Get-Command Export-WindowsFirewallRules -ErrorAction SilentlyContinue) {
            Export-WindowsFirewallRules -FilePath "C:\backup\firewall-rules.wfw"
            $resultFW.Text = "Exported using Export-WindowsFirewallRules to C:\backup\firewall-rules.wfw"
        } else {
            $output = Invoke-ExternalCommand -Command "netsh.exe" -Arguments @("advfirewall", "export", "C:\backup\firewall-rules.wfw")
            $resultFW.Text = "Exported using netsh to C:\backup\firewall-rules.wfw`n$($output)"
        }
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Enable Logging" 20 220 {
    try {
        Set-NetFirewallProfile -LogAllowed True -LogBlocked True
        $resultFW.Text = "Firewall logging enabled (allowed and blocked connections)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Disable Logging" 320 220 {
    try {
        Set-NetFirewallProfile -LogAllowed False -LogBlocked False
        $resultFW.Text = "Firewall logging disabled (allowed and blocked connections)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Configure ICMP (Allow Ping)" 20 270 {
    try {
        New-NetFirewallRule -Name "Allow Ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -ErrorAction Stop
        $resultFW.Text = "Firewall rule created to allow inbound ping (ICMPv4)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Configure ICMP (Block Ping)" 320 270 {
    try {
        New-NetFirewallRule -Name "Block Ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Block -ErrorAction Stop
        $resultFW.Text = "Firewall rule created to block inbound ping (ICMPv4)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}
Add-FWPSButton $tabFW "Check Firewall State (Current Profile Only)" 20 320 {
    try {
        $profile = (Get-NetConnectionProfile).NetworkCategory
        $output = Get-NetFirewallProfile -Profile $profile | Format-List | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
}

# ---- Tab 4: Tooltips ----
$tabTooltips = New-Object System.Windows.Forms.TabPage
$tabTooltips.Text = "Tooltips"
$tabs.Controls.Add($tabTooltips)

$tooltipsText = @"
HOST TOOLS

Ping: Test host reachability via ICMP echo
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ping

Tracert: Trace packet route to host
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tracert

Nmap: Port and service scan (requires nmap installed)
    https://nmap.org/book/man.html

Test-NetConnection: Modern PowerShell connectivity test
    https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection

Nslookup: DNS query for host or IP
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/nslookup

LOCAL TOOLS

Check Network: List IPv4 interfaces (netsh)
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh

Show Routes: Show system routing table
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/route

Network Category: Show current network profile
    https://learn.microsoft.com/en-us/powershell/module/netconnection

Get Logs: View last 20 system events
    https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog

Get IP Config: View all adapter configuration
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig

Release IP: Release all DHCP addresses (ipconfig /release)
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig

Renew IP: Request new DHCP addresses (ipconfig /renew)
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig

Show DNS Cache: Display DNS resolver cache
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig

Flush DNS: Clear DNS resolver cache
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ipconfig

List TCP Connections: Show active TCP connections
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat

Show Net Shares: List SMB shares
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-share

Check Port Usage: Show all active ports and processes
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat

ARP -a: Display ARP table
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp

FIREWALL

Check Firewall Status (All profiles): Show state for each firewall profile
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile

View Current Firewall Settings (Detailed): Show all firewall settings
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile

Enable/Disable Firewall (All profiles): Set state for Domain, Public, and Private
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile

List All Firewall Rules: List all rules (name, state, action)
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule

List Firewall Rules by Port: List port filter rules
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter

Reset Firewall Settings: Restore firewall to default
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile

Export Firewall Rules: Export rules to file
    https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-advfirewall-export

Enable/Disable Logging: Control allowed/blocked logging
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile

Configure ICMP (Allow/Block Ping): Add or remove ping rules
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule

Check Firewall State (Current Profile): Show firewall state for active profile
    https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile

"@

$tooltipsBox = New-Object System.Windows.Forms.TextBox
$tooltipsBox.Multiline = $true
$tooltipsBox.ScrollBars = "Vertical"
$tooltipsBox.Location = New-Object System.Drawing.Point(20, 20)
$tooltipsBox.Size = New-Object System.Drawing.Size(820, 520)
$tooltipsBox.Font = New-Object System.Drawing.Font("Consolas", 10)
$tooltipsBox.Text = $tooltipsText
$tooltipsBox.ReadOnly = $true
$tabTooltips.Controls.Add($tooltipsBox)

# ---- Tab 5: About ----
$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = "About"
$tabs.Controls.Add($tabAbout)

$aboutLabel = New-Object System.Windows.Forms.Label
$aboutLabel.Text = "Network Tools GUI`n`nCreated by Alan O'Brien`n`nFor troubleshooting and diagnostics.`n"
$aboutLabel.Location = New-Object System.Drawing.Point(20, 20)
$aboutLabel.Size = New-Object System.Drawing.Size(700, 200)
$aboutLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$tabAbout.Controls.Add($aboutLabel)

[void]$form.ShowDialog()
