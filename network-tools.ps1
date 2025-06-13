# network-gui2.ps1
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

$toolTip = New-Object System.Windows.Forms.ToolTip

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
$toolTip.SetToolTip($pingBtn, "Send ICMP echo requests to test network reachability.")

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
$toolTip.SetToolTip($tracertBtn, "Trace the route packets take to a network host.")

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
$toolTip.SetToolTip($nmapBtn, "Run nmap scan against the target. Enter ports as comma-separated or a range.")

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
$toolTip.SetToolTip($testNetBtn, "Test TCP port and connectivity with PowerShell's Test-NetConnection.")

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
$toolTip.SetToolTip($nslookupBtn, "Query DNS for information about the target host or IP.")

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

# Check Network
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
$toolTip.SetToolTip($checkNetBtn, "Display IPv4 interface list and status using netsh.")

# Show Routes
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
$toolTip.SetToolTip($routesBtn, "Show current IP routing table.")

# Network Category
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
$toolTip.SetToolTip($netCatBtn, "Show the current network connection profile/category.")

# Get Logs
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
$toolTip.SetToolTip($getLogsBtn, "Display the last 20 entries from the System event log.")

# Get IP Config
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
$toolTip.SetToolTip($getIPCfgBtn, "Show full IP configuration for all adapters.")

# Show DNS Cache
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
$toolTip.SetToolTip($dnsCacheBtn, "Display the contents of the DNS resolver cache.")

# Flush DNS
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
$toolTip.SetToolTip($flushDNSBtn, "Clear the contents of the DNS resolver cache.")

# List TCP Connections
$tcpConnBtn = New-Object System.Windows.Forms.Button
$tcpConnBtn.Text = "List TCP Connections"
$tcpConnBtn.Location = New-Object System.Drawing.Point(340, 70)
$tcpConnBtn.Size = New-Object System.Drawing.Size(160, 35)
$tcpConnBtn.Add_Click({
    $resultLocal.Text = "Listing TCP connections ..."
    $output = Invoke-ExternalCommand -Command "netstat.exe" -Arguments @("-n")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($tcpConnBtn)
$toolTip.SetToolTip($tcpConnBtn, "Show all active TCP connections.")

# Show Net Shares
$netSharesBtn = New-Object System.Windows.Forms.Button
$netSharesBtn.Text = "Show Net Shares"
$netSharesBtn.Location = New-Object System.Drawing.Point(520, 70)
$netSharesBtn.Size = New-Object System.Drawing.Size(100, 35)
$netSharesBtn.Add_Click({
    $resultLocal.Text = "Listing network shares ..."
    $output = Invoke-ExternalCommand -Command "net.exe" -Arguments @("share")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($netSharesBtn)
$toolTip.SetToolTip($netSharesBtn, "Show all shared folders on this system.")

# Check Port Usage
$portUsageBtn = New-Object System.Windows.Forms.Button
$portUsageBtn.Text = "Check Port Usage"
$portUsageBtn.Location = New-Object System.Drawing.Point(640, 70)
$portUsageBtn.Size = New-Object System.Drawing.Size(120, 35)
$portUsageBtn.Add_Click({
    $resultLocal.Text = "Checking port usage ..."
    $output = Invoke-ExternalCommand -Command "netstat.exe" -Arguments @("-ano")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($portUsageBtn)
$toolTip.SetToolTip($portUsageBtn, "Show all TCP/UDP connections with process IDs.")

# ARP -a
$arpBtn = New-Object System.Windows.Forms.Button
$arpBtn.Text = "ARP -a"
$arpBtn.Location = New-Object System.Drawing.Point(20, 120)
$arpBtn.Size = New-Object System.Drawing.Size(100, 35)
$arpBtn.Add_Click({
    $resultLocal.Text = "Running arp -a ..."
    $output = Invoke-ExternalCommand -Command "arp.exe" -Arguments @("-a")
    $resultLocal.Text = $output
})
$tabLocal.Controls.Add($arpBtn)
$toolTip.SetToolTip($arpBtn, "Display the system ARP table (address resolution protocol).")

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
    param($tab, $text, $locX, $locY, $scriptblock, $tooltip)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text = $text
    $btn.Location = New-Object System.Drawing.Point($locX, $locY)
    $btn.Size = New-Object System.Drawing.Size(270, 35)
    $btn.Add_Click($scriptblock)
    $tab.Controls.Add($btn)
    $toolTip.SetToolTip($btn, $tooltip)
}

Add-FWPSButton $tabFW "Check Firewall Status (All profiles)" 20 20 {
    try {
        $output = Get-NetFirewallProfile | Format-Table Name, Enabled | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Show enabled/disabled state for all firewall profiles."

Add-FWPSButton $tabFW "View Current Firewall Settings (Detailed)" 320 20 {
    try {
        $output = Get-NetFirewallProfile -PolicyStore ActiveStore | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "View detailed settings for all firewall profiles (active store)."

Add-FWPSButton $tabFW "Enable Firewall (All profiles)" 20 70 {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        $resultFW.Text = "Firewall enabled for all profiles."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Enable firewall on all profiles."

Add-FWPSButton $tabFW "Disable Firewall (All profiles)" 320 70 {
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        $resultFW.Text = "Firewall disabled for all profiles."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Disable firewall on all profiles."

Add-FWPSButton $tabFW "List All Firewall Rules" 20 120 {
    try {
        $output = Get-NetFirewallRule | Select-Object DisplayName, Enabled, Action, Direction | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "List all configured firewall rules."

Add-FWPSButton $tabFW "List Firewall Rules by Port" 320 120 {
    try {
        $output = Get-NetFirewallPortFilter | Select-Object LocalPort, Protocol, @{N='RuleName';E={$_.InstanceID}} | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "List all firewall rules that use a port filter."

Add-FWPSButton $tabFW "Reset Firewall Settings to Default" 20 170 {
    try {
        (New-Object -ComObject HNetCfg.FwPolicy2).RestoreLocalFirewallDefaults()
        $resultFW.Text = "Firewall settings reset to default."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Restore all firewall settings to default."

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
} "Export all firewall rules to a file (PowerShell or netsh fallback)."

Add-FWPSButton $tabFW "Enable Logging" 20 220 {
    try {
        Set-NetFirewallProfile -LogAllowed True -LogBlocked True
        $resultFW.Text = "Firewall logging enabled (allowed and blocked connections)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Enable firewall logging for allowed and blocked connections."

Add-FWPSButton $tabFW "Disable Logging" 320 220 {
    try {
        Set-NetFirewallProfile -LogAllowed False -LogBlocked False
        $resultFW.Text = "Firewall logging disabled (allowed and blocked connections)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Disable firewall logging for allowed and blocked connections."

Add-FWPSButton $tabFW "Configure ICMP (Allow Ping)" 20 270 {
    try {
        New-NetFirewallRule -Name "Allow Ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Allow -ErrorAction Stop
        $resultFW.Text = "Firewall rule created to allow inbound ping (ICMPv4)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Create a rule to allow inbound ICMP (ping) requests."

Add-FWPSButton $tabFW "Configure ICMP (Block Ping)" 320 270 {
    try {
        New-NetFirewallRule -Name "Block Ping" -Protocol ICMPv4 -IcmpType 8 -Direction Inbound -Action Block -ErrorAction Stop
        $resultFW.Text = "Firewall rule created to block inbound ping (ICMPv4)."
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Create a rule to block inbound ICMP (ping) requests."

Add-FWPSButton $tabFW "Check Firewall State (Current Profile Only)" 20 320 {
    try {
        $profile = (Get-NetConnectionProfile).NetworkCategory
        $output = Get-NetFirewallProfile -Profile $profile | Format-List | Out-String
        $resultFW.Text = $output
    } catch {
        $resultFW.Text = "Error: $($_.Exception.Message)"
    }
} "Show firewall state for the active network profile only."

# ---- Tab 4: About ----
$tabAbout = New-Object System.Windows.Forms.TabPage
$tabAbout.Text = "About"
$tabs.Controls.Add($tabAbout)

$aboutLabel = New-Object System.Windows.Forms.Label
$aboutLabel.Text = "Network Tools GUI`n`nCreated by Alan O'Brien`n`nFor troubleshooting and diagnostics.`n"
$aboutLabel.Location = New-Object System.Drawing.Point(20, 20)
$aboutLabel.Size = New-Object System.Drawing.Size(700, 200)
$aboutLabel.Font = New-Object System.Drawing.Font("Segoe UI", 12)
$tabAbout.Controls.Add($aboutLabel)

# ---- Show the Form ----
[void]$form.ShowDialog()
