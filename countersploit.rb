######################################################################################
######################################################################################
# countersploit - live-response w/ msf
######################################################################################
######################################################################################

#
######################################################################################
# Configurable variables: change things in this section as needed
######################################################################################
#
# process names for migration targets
@process_targets = [ "winlogon.exe", "svchost.exe" ]
#
# max lines to display to screen (for most cmds); all lines are captured in audit/
@display_lines = 150
#
######################################################################################
# Thar be dragons below...
######################################################################################
#
@client = client
@SELF = "countersploit"
@BANNER = '.:/|=-~> ' + @SELF + '.rb <~-=|\\:.'
@HOSTID = @client.sys.config.sysinfo['Computer']
@HOMEPATH=::File.join(Msf::Config.config_directory, @SELF) 
@C2PATH=::File.join(@HOMEPATH, 'c2')
@AUDITPATH=::File.join(@HOMEPATH, 'audit')
@LIBPATH=::File.join(@HOMEPATH, 'lib')
@BINPATH=::File.join(@HOMEPATH, 'bin')
@ETCPATH=::File.join(@HOMEPATH, 'etc')

#
######################################################################################
# init - load and initialize classes, and create required directories
######################################################################################
#
def init() 

   # load up supporting classes
   load ::File.join(@LIBPATH, "Audit.rb")
   load ::File.join(@LIBPATH, "FS.rb")
   load ::File.join(@LIBPATH, "System.rb")

   @audit = Audit.new(@client, @AUDITPATH, @HOSTID, @display_lines)
   @fs = FS.new(@client, @audit, @BINPATH) 
   @sys = System.new(@client, @fs, @audit, @BINPATH) 
   @hostCmd = ::File.join(@C2PATH, "#{@audit.auditID}.cmd")
   @generalCmd = ::File.join(@C2PATH, "general.cmd")

   ::FileUtils.mkdir_p(@C2PATH)
   ::FileUtils.mkdir_p(@AUDITPATH)
   ::FileUtils.mkdir_p(@LIBPATH)

end

#
######################################################################################
# touchBase - ensure general and specific command files exist
######################################################################################
#
def touchBase() 
   begin
      if not ::File.exists?(@hostCmd)
         @audit.lpStatus("Creating blank host cmd file (#{@hostCmd})")
         file_local_write(@hostCmd, "")
      end
      if not ::File.exists?(@generalCmd)
        @audit.lpStatus("Creating a blank general cmd file (#{@generalCmd})")
        file_local_write(@generalCmd, "")
      end
   rescue ::Exception => e
      @audit.lpError("ERROR: touchBase: #{e.class} - #{e}")
      raise Rex::Script::Completed
   end
end

#
######################################################################################
# getPrivs - attempt to get SYSTEM
######################################################################################
#
def getPrivs
   begin
      #
      # check for system perms, and try for them if needed
      #
      rslt=false
      if not is_system?
         @audit.lpStatus("Running as #{@client.sys.config.getuid}, trying to get SYSTEM")
         begin
            rslt = @client.priv.getsystem
         rescue Rex::Post::Meterpreter::RequestError => re
            if "#{re}" =~ /Access is denied/
            else
               @audit.lpError("ERROR: getPrivs: #{re.class} - #{re}")
               return
            end
         end
         if rslt
            @audit.lpGood("Got SYSTEM")
         else
            @audit.lpError("WARNING: Unable to obtain SYSTEM perms; functionality will be degraded")
         end
      end
      @audit.lpStatus("Running as #{@client.sys.config.getuid}")
      @audit.is_system = is_system?
      @audit.lpStatus("SYSTEM := #{@audit.is_system}")
      @audit.is_admin = is_admin?
      @audit.lpStatus("Admin := #{@audit.is_admin}")
   rescue ::Exception => e
      @audit.lpError("ERROR: getPrivs: #{e.class} - #{e}")
   end
end

#
######################################################################################
# migratePID - migrate to one of the target PIDs defined in @process_targets
######################################################################################
#
def migratePID()
   begin
      origPID = @client.sys.process.getpid
      #
      # record the PIDs of processes w/ the process names we're searching for
      #
      tPIDs = []
      @client.sys.process.get_processes().each do |x|
         tPIDs.push(x['pid']) if @process_targets.grep(/^#{x['name']}$/i).length > 0
      end
      if tPIDs.length == 0
         @audit.lpError("Unable to find any PID migration targets (check @process_targets in countersploit.rb)")
         return
      end
      #
      # check if we're already running as a target process
      #
      if tPIDs.grep(origPID).length > 0
         tName=""
         @client.sys.process.get_processes().each do |x|
            if x['pid'] == origPID 
               tName = x['name']
               break
            end
         end
         @audit.lpStatus("Already running as a target PID (#{origPID} - #{tName})")
         return
      end
      #
      # migrate to one of the targets
      #
      tPIDs.each do |p|
         tName=""
         @client.sys.process.get_processes().each do |x|
            if x['pid'] == p
               tName = x['name']
               break
            end
         end
         @audit.lpStatus("Attempting to migrate to PID: #{p} (#{tName})")
         begin
            client.core.migrate(p)
         rescue Rex::Post::Meterpreter::RequestError => re
            if "#{re}" =~ /core_migrate: Operation failed: Access is denied/
               @audit.lpError("Unable to migrate to #{p} (Access Denied)") 
            else
               @audit.lpError("ERROR: migratePID: #{re.class} - #{re}")
               return
            end
         rescue Rex::RuntimeError => r
            if "#{r}" =~ /insufficient privileges/
               @audit.lpError("Unable to migrate to #{p} (Insufficient Privileges)")
            else
               @audit.lpError("ERROR: migratePID: #{r.class} - #{r}")
               return
            end
         end
         if @client.sys.process.getpid == p
            @audit.lpStatus("Migration complete!")
            #
            # sometimes old PIDs are cleaned up after migration, and sometimes they hang out, so try to kill...
            #
            @client.sys.process.get_processes().each do |x|
               if x['pid'] == origPID
                  @audit.lpStatus("Killing old PID: #{origPID}")
                  @client.sys.process.kill(origPID)
                  break
               end
            end
            return
         end
      end
      #
      # should only get here if no migration worked...
      #
      @audit.lpError("Migration failed...") if origPID == @client.sys.process.getpid
   rescue ::Exception => e
      @audit.lpError("ERROR: migratePID: #{e.class} - #{e}")
   end
end

#
######################################################################################
# readWhitelist - parse the whitelist file and return an array of hashes to be ignored
######################################################################################
#
def readWhitelist
   wlFile = @ETCPATH + "/whitelist.txt"
   wlArr = []
   begin
      if ::File.exists?(wlFile)
         ::File.open(wlFile, "r").each_line do |line|
            # no leading or trailing spaces
            line.strip!
            # no newlines
            line.chomp!
            # strip out comments
            line[/#.*/]="" if line =~ /#/
            # no lines that are too short
            next if line.length < 32
            # read the first 32 chars (to allow inline comments w/o using #)
            tmp = line[0..31]
            # no lines that contain non-hex chars
            next if tmp !~ /[0-9a-f]{32}/i
            wlArr.push(tmp.upcase)
         end
      else
         @audit.lpError("ERROR: readWhitelist: Unable to read whitelist file: #{@ETCPATH}/whitelist.txt")
         raise Rex::Script::Completed
      end
   rescue ::Exception => e
      @audit.lpError("ERROR: readWhitelist: #{e.class} - #{e}")
   end
   wlArr.uniq
end

#
######################################################################################
# checkC2 - parse commands rcv'd via cli and/or .cmd files...
######################################################################################
#
def checkC2(known_cmds, cmd_list) 
   begin
      #
      # any cmd's via cli were pushed on during opt parsing
      #
      if cmd_list.length > 0
         @audit.lpStatus("Commands rcv'd via CLI:")
         cmd_list.each do |cl|
            @audit.lpStatus("\t#{cl}")
         end
      end

      #
      # read host specific cmd list
      #
      @audit.lpStatus("Checking for #{@hostCmd}")
      if ::File.exists?(@hostCmd)
         ::File.open(@hostCmd, "r").each_line do |line|
            line.chomp!
            if known_cmds.grep(/^#{line.split[0]}/i).length > 0
               cmd_list.push(line)
               @audit.lpStatus("\tRcv'd cmd: #{line}")
            else
               @audit.lpError("\tUnknown cmd: #{line}")
            end
         end
      end

      #
      # read general cmd list
      #
      @audit.lpStatus("Checking for #{@generalCmd}")
      if ::File.exists?(@generalCmd)
         ::File.open(@generalCmd, "r").each_line do |line|
            line.chomp!
            if known_cmds.grep(/^#{line.split[0]}/i).length > 0
               cmd_list.push(line)
               @audit.lpStatus("\tRcv'd cmd: #{line}")
            else
               @audit.lpError("\tUnknown cmd: #{line}")
            end
         end
      end

      #
      # parse n exec cmds
      #
      @audit.lpStatus("Executing #{cmd_list.length} queued commands...")
      cmd_list.each do |line|
         case line
         ########################################################################
         when /^hash/i
         ########################################################################
            @audit.lpStatus("Executing hash...")
            hashFiles=[]
            wlArr=[]
            line[/^hash/i]=""
            hOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-f" => [true, "Pipe-delimited (\"|\") list of files to hash"],
               "-F" => [true, "Path to a file containing a list of hash targets/paths (one per line)"], 
               "-W" => [false, "Only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            hOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Hash Help Menu\n\nFiles are hashed\nDirectories are enumerated, but not recursed\n#{hOpts.usage}")
                  return
               when "-f"
                  hashFiles = val.split("|")
               when "-F"
                  if ::File.exists?(val)
                     ::File.open(val, "r").each_line do |line|
                        hashFiles.push(line.chomp)
                     end
                  else
                     @audit.lpError(" Unable to read file: #{val}")
                     raise Rex::Script::Completed
                  end
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @fs.hash(hashFiles, wlArr)
         ########################################################################
         when /^system-info/i
         ########################################################################
            @audit.lpStatus("Executing system-info...")
            line[/system-info/i] = ""
            siOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"], )
            siOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                 @audit.lpStatus("   System-Info Help Menu\n\nCurrently this feature supports no options; execute it with no parameters...\n")
                 return
              else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.system_info()
         ########################################################################
         when /^startup-items/i
         ########################################################################
            @audit.lpStatus("Executing startup-items...")
            line[/startup-items/i]=""
            stiOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-x" => [false, "Calculate the MD5 hash of the startup executable"], 
               "-W" => [false, "If hashing, only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            startupHash=false
            wlArr=[]
            stiOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Startup-Items Help Menu\n#{stiOpts.usage}")
                  return
               when "-x"
                  startupHash=true
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.startup_items(startupHash, wlArr)
         ########################################################################
         when /^fs-list/i
         ########################################################################
            @audit.lpStatus("Executing fs-list...")
            line[/fs-list/i] = ""
            fslOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu." ],
               "-p" => [true, "Path to search.\n\t\t==> You can use envars (ex: %TEMP%), but remember they might change depending on your running user context (user vs SYSTEM)\n\t\t==> WARNING: Spaces break things, so use DOS style names where needed :(\n\t\t==> If this opt isn't given, all available drives will be logged and the script quits\n\t\t==> If the opt val is \"all\", all drives will be enumerated, but fs stats and hashes will not be performed"],
               "-s" => [true, "Search blobs (*.txt, *, etc) delimited by a |.  [Default is *]"],
               "-N" => [false, "Display native (epoch) fs times [Default is false]"],
               "-R" => [false, "Do not recurse. [Default is to recurse]"],
               "-d" => [false, "Stat for file details. [Default is false]"],
               "-x" => [false, "Hash the file (WARNING: can be consuming...). [Default is false]"],
               "-B" => [true, "Bound the search results by time\n\t\t==> Possible values are ATIME, MTIME, and CTIME (indicating which time will bound the search)\n\t\t==> Using this param requires the use of -U and -L for upper and lower search boundaries"],
               "-U" => [true, "Upper date/time boundary for use with -B\n\t\t==> format is: YYYYMMDDHHmmSS (ex: 20120519223146 == 19May2012 10:31:46PM)\n\t\t==> all times are UTC/Zulu"],
               "-L" => [true, "Lower date/time boundary for use with -B\n\t\t==> format is: YYYYMMDDHHmmSS (ex: 20120519000000 == 19May2012 12:00:00AM)\n\t\t==> all times are UTC/Zulu"],
               "-W" => [false, "If hashing, only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            fslPath=fslBound=fslUpper=fslLower=nil
            fslBlobs=["*"]
            fslRecurse=true
            fslDetails=false
            fslHash=false
            fslNativeTime=false
            wlArr=[]
            fslOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("FS-List Help Menu\n#{fslOpts.usage}")
                  return
               when "-p"
                  fslPath=val
               when "-s"
                  fslBlobs=val.split("|")
               when "-R"
                  fslRecurse=false
               when "-d"
                  fslDetails=true
               when "-x"
                  fslHash=true
               when "-N"
                  fslNativeTime=true
               when "-B"
                  fslBound=val
               when "-U"
                  fslUpper=val
               when "-L"
                  fslLower=val
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError(" Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @fs.list(fslPath, fslBlobs, fslRecurse, fslDetails, fslHash, fslNativeTime, fslBound, fslUpper, fslLower, wlArr)
         ########################################################################
         when /^process-list/i
         ########################################################################
            @audit.lpStatus("Executing process-list...")
            line[/process-list/i]=""
            plOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-x" => [false, "Calculate the MD5 hash of the process executable"], 
               "-W" => [false, "If hashing, only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            procHash=false
            wlArr=[]
            plOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Process-List Help Menu\n#{plOpts.usage}")
                  return
               when "-x"
                  procHash=true
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.process_list(procHash, wlArr)
         ########################################################################
         when /^service-list/i
         ########################################################################
            @audit.lpStatus("Executing service-list...")
            line[/service-list/i]=""
            svlOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-x" => [false, "Calculate the MD5 hash of the service executable (and service DLL if applicable)"], 
               "-W" => [false, "If hashing, only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            svcHash=false
            wlArr=[]
            svlOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Service-List Help Menu\n#{svlOpts.usage}")
                  return
               when "-x"
                  svcHash=true
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.service_list(svcHash, wlArr)
         ########################################################################
         when /^driver-list/i
         ########################################################################
            @audit.lpStatus("Executing driver-list...")
            line[/driver-list/i]=""
            dlOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-x" => [false, "Calculate the MD5 hash of the driver file"], 
               "-W" => [false, "If hashing, only record/return findings that aren't found in the whitelist (etc/whitelist.txt)"], )
            driverHash=false
            wlArr=[]
            dlOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Driver-List Help Menu\n#{dlOpts.usage}")
                  return
               when "-x"
                  driverHash=true
               when "-W"
                  wlArr=readWhitelist()
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.driver_list(driverHash, wlArr)
         ########################################################################
         when /^job-list/i
         ########################################################################
            @audit.lpStatus("Executing job-list...")
            line[/job-list/i] = ""
            jlOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"], )
            jlOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Job-List Help Menu\n\nCurrently this feature supports no options; execute it with no parameters...\n")
                  return
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.job_list()
         ########################################################################
         when /^system-log/i
         ########################################################################
            @audit.lpStatus("Executing system-log...")
            line[/system-log/i] = ""
            slOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu" ],
               "-t" => [false, "Tail the log results, returning only new(ish) data (may be minor overlap)"], )
            slApp=slSec=slSys=true
            slTail=false
            slOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   System-Log Help Menu\n#{slOpts.usage}")
                  return
               when "-t"
                  slTail=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.system_log(slTail)
         ########################################################################
         when /^ads-list/i
         ########################################################################
            @audit.lpStatus("Executing ads-list...")
            line[/ads-list/i]=""
            alOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu" ],
               "-p" => [true, "Path to search.\n\t\t==> WARNING: use DOS style names b/c spaces break things :(\n\t\t==> If this opt isn't given, %SYSTEMDRIVE% will be searched" ], )
            alPath=nil
            alOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   ADS List Help Menu\n#{alOpts.usage}")
                  return
               when "-p"
                  alPath=val
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @fs.ads_list(alPath)
         ########################################################################
         when /^process-mem-capture/i
         ########################################################################
            @audit.lpStatus("Executing process-mem-capture...")
            line[/process-mem-capture/i]=""
            pmcOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu" ],
               "-p" => [true, "Process PID to capture" ],
               "-M" => [false, "Capture process image as well associated image modules (each in separate files)" ],
               "-F" => [false, "Capture entire process image space in a single file" ], )
               #"-C" => [false, "Compare the captured memory image(s) to the associated file(s) on disk (not compatible with -F)"], )
            pmcPID=nil
            pmcModules=false
            pmcFull=false
            pmcOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Process Memory Capture Help Menu\n#{pmcOpts.usage}")
                  return
               when "-p"
                  pmcPID=val
               when "-M"
                  pmcModules=true
               when "-F"
                  pmcFull=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.process_mem_capture(pmcPID, pmcModules, pmcFull)
         ########################################################################
         when /^registry-capture/i
         ########################################################################
            @audit.lpStatus("Executing registry-capture...")
            line[/registry-capture/i]=""
            rlOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu" ],
               "-r" => [true, "Root key (HKLM|HKCU|HKCR|HKU|HKCC) [REQUIRED]" ],
               "-s" => [true, "Sub key (use double-slashes; ex: SOFTWARE\\\\Microsoft) [OPTIONAL]\nNOTE: When passing subkey info w/ \\ (ie: software\\microsoft), do so from a .cmd file, because using -c on the meterpreter CLI results in the delimeters disapearing" ],
               "-H" => [false, "Output as .hiv file [Default is .reg]" ], )
            rootKey=""
            subKey=""
            hive=false
            rlOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Registry Capture Help Menu\n#{rlOpts.usage}")
                  return
               when "-r"
                  rootKey=val.strip
               when "-s"
                  subKey=val.strip
               when "-H"
                  hive=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.registry_capture(rootKey, subKey, hive)
         ########################################################################
         when /^net-list/i
         ########################################################################
            @audit.lpStatus("Executing net-list...")
            line[/net-list/i]=""
            nlOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu" ],
               "-N" => [false, "Omit netstat listing" ],
               "-A" => [false, "Omit arp listing" ],
               "-r" => [false, "Include route listing" ],
               "-z" => [false, "Include hosts listing" ],
               "-i" => [false, "Include detailed ipconfig listing" ], )
            netstat=true
            arp=true
            hosts=false
            route=false
            ipconfig=false
            nlOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Network Listing Help Menu\n#{nlOpts.usage}")
                  return
               when "-N"
                  netstat=false
               when "-A"
                  arp=false
               when "-r"
                  route=true
               when "-z"
                  hosts=true
               when "-i"
                  ipconfig=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.net_list(netstat, arp, route, hosts, ipconfig)
         ########################################################################
         when /^restore-point-list/i
         ########################################################################
            @audit.lpStatus("Executing restore-point-list...")
            line[/restore-point-list/i]=""
            rplOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"], )
            rplOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Restore-Point-List Help Menu\n\nCurrently this feature supports no options; execute it with no parameters...\n")
                  return
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.restore_point_list()
         ########################################################################
         when /^isolate/i
         ########################################################################
            @audit.lpStatus("Executing isolate...")
            line[/isolate/i]=""
            iOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-i" => [false, "Isolate via layer-3 (IP)\n\t\t==> WARNING!!!: Sends data to the network ID (.0 on a /24), which is kinda null on modern networks, but could create serious DoS conditions on older networks\n\t\t==> Works by adding a specific route for MSF to the existing gateway, then adds a default route to the network ID"],
               "-a" => [false, "Isolate via layer-2 (ARP)\n\t\t==> adds invalid ARP entries for all local IP except the client lan ip, the default gate ip, and the MSF server ip (if local)"],
               "-d" => [false, "Isolate via DNS\n\t\t==> WARNING!!!: Sends data to the network ID (.0 on a /24), which is kinda null on modern networks, but could create serious DoS conditions on older networks\n\t\t==> Creates null routes for current DNS servers"],
               "-X" => [false, "Undo any existing isolation"], )
            l3=false
            l2=false
            dns=false
            undo=false
            iOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Isolate Help Menu\n#{iOpts.usage}")
                  return
               when "-i"
                  l3=true
               when "-a"
                  l2=true
               when "-d"
                  dns=true
               when "-X"
                  undo=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.isolate(dns, l3, l2, undo)
         ########################################################################
         when /^monitor/i
         ########################################################################
            @audit.lpStatus("Executing monitor...")
            line[/monitor/i]=""
            mOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-d" => [true, "Comma-delimited list of domains to point to localhost via hosts file (ex: www.foo.com,www.bork.edu,bork.edu)"],
               "-D" => [true, "Path to local file containing list of domains to point to localhost via hosts file (one per line)"],
               "-L" => [true, "Proxy local port to remote address: localPort:remoteProxyAddress:remoteProxyPort (ex: -L 80:1.2.3.4:8080)"],
               "-p" => [true, "Password for ssh tunnel (note: this pass will be logged in the audit logs, and note we don't support blank pass atm [nor cert auth])"],
               "-u" => [true, "Username for ssh tunnel"],
               "-i" => [true, "IP for ssh tunnel"],
               "-X" => [false, "Teardown previous connections and undo changes to the hosts file"], )
            hosts=""
            portNfo=""
            pass=""
            user=""
            ip=""
            teardown=false
            mOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Monitor Help Menu\n#{mOpts.usage}")
                  return
               when "-d"
                  hosts=val
               when "-D"
                  if ::File.exists?(val)
                     ::File.open(val, "r").each_line do |line|
                        line.chomp!
                        hosts+="#{line},"
                     end
                     hosts[/,$/]="" if hosts =~ /,$/
                  else
                     @audit.lpError(" Unable to read file: #{val}")
                     raise Rex::Script::Completed
                  end
               when "-L"
                  portNfo=val
               when "-p"
                  pass=val
               when "-u"
                  user=val
               when "-i"
                  ip=val
               when "-X"
                  teardown=true
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.monitor(teardown, ip, user, pass, portNfo, hosts)
         ########################################################################
         when /^gather-file/i
         ########################################################################
            @audit.lpStatus("Executing gather-file...")
            line[/gather-file/i]=""
            gfOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-n" => [true, "Name (a string of your choice to be included in the file name after download)"],
               "-f" => [true, "Path to the file to download"], )
            fName=""
            fPath=""
            gfOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Gather-File Help Menu\n#{gfOpts.usage}")
                  return
               when "-n"
                  fName=val.strip
               when "-f"
                  fPath=val.strip
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @audit.gatherFile(fName, fPath)
         ########################################################################
         when /^autoruns/i
         ########################################################################
            @audit.lpStatus("Executing autoruns...")
            line[/autoruns/i]=""
            arOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"],
               "-a" => [true, "Execute autoruns with the -a (all) param"],
               "-V" => [true, "Execute autoruns without verifying digital signatures"], )
            arAll=false
            arVrfy=true
            arOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Autoruns Help Menu\n#{arOpts.usage}")
                  return
               when "-a"
                  arAll=true
               when "-V"
                  arVrfy=false
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.autoruns(arVrfy, arAll)
         ########################################################################
         when /^raw-mem-dump/i
         ########################################################################
            @audit.lpStatus("Executing raw mem dump...")
            line[/raw-mem-dump/i]=""
            rmdOpts = Rex::Parser::Arguments.new(
               "-h" => [false, "Help menu"], )
            rmdOpts.parse(line.strip.split) { |opt, idx, val|
               case opt
               when "-h"
                  @audit.lpStatus("   Raw Mem Dump Help Menu\n\nCurrently this feature supports no options; execute it with no parameters...\n")
                  return
               else
                  @audit.lpError("   Unknown option: \"#{opt} #{val}\"")
                  return
               end
            }
            @sys.raw_mem_dump()
         else
            @audit.lpError("WARNING: Unknown cmd: #{line}")
         end
      end
   rescue ::Exception => e
      @audit.lpError("checkC2: #{e.class} - #{e}")
      raise Rex::Script::Completed
   end
end


######################################################################################
# main 
######################################################################################
knownCmds = ["hash", "system-info", "startup-items", "fs-list", "process-list", "service-list", 
             "driver-list", "system-log", "job-list", "net-list", "ads-list", "restore-point-list",
             "process-mem-capture", "registry-capture", "isolate", "monitor", "gather-file", "autoruns",
             "raw-mem-dump", ]
knownCmds.sort!
cmdList = []

@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false, "This help menu" ],
        "-l" => [ false, "List available commands" ],
        "-c" => [ true,  "Execute a command (use multiple times for multiple cmds) (use single quotes on target paths in meter cli)" ] )

@@exec_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
         print_line "\n#{@BANNER}\n"
         print_line(@@exec_opts.usage)
         return
      when "-l"
         print_line "\n#{@BANNER}\n"
         print_line "Available Commands:"
         knownCmds.each do |c|
            print_line "   - #{c}"
         end
         print_line ""
         return
      when "-c"
         if knownCmds.grep(/^#{val.split[0]}/i).length > 0
            cmdList.push(val)
         else
            print_error("ERROR: Unsupported CLI cmd: #{val}")
            return
         end
      else
         #NOTE: never seem to get here... msf bug?
         print_error "ERROR: Unknown CLI command: #{opt}"
         return
      end
}

#
# sanity check 
#
if @client.platform !~ /win32|win64/
   print_error("#{@HOSTID}: #{@client.platform} not currently supported")
   print_error("#{@HOSTID}: #{@client.sys.config.sysinfo}")
   return
end

#
# initialize required classes, etc
#
init()

@audit.lpStatus("##################################################")
@audit.lpStatus("#{@audit.auditID}: *~* Executing *~*")
@audit.lpStatus("##################################################")

#
# prepare to execute
#
touchBase()
getPrivs()
migratePID()

#
# check commands and execute
#
checkC2(knownCmds, cmdList)

@audit.lpStatus("##################################################")
@audit.lpStatus("#{@audit.auditID}: *~* Complete *~*")
@audit.lpStatus("##################################################")
