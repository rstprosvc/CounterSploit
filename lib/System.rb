class System 

   #
   ######################################################################################
   # initialize
   ######################################################################################
   #
   def initialize(session, fs, logger, binpath)
      @session = session
      @fs = fs
      @logger = logger
      @binpath = binpath
   end

 protected

   #
   ######################################################################################
   # enum_local_users - by reading reg values... (tx jduck!)
   ######################################################################################
   #
   def enum_local_users()
      if @logger.is_system == false
         @logger.lpError("   ERROR: Unable to enumerate local users without SYSTEM...")
         return
      end
      users = {}
      uk = nil
      ok = @session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names", KEY_READ)
      ok.enum_key.each do |usr|
         uk = @session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users\\Names\\#{usr}", KEY_READ)
         r = uk.query_value("")
         rid = r.type
         users[rid] ||= {}
         users[rid][:Name] = usr
      end
      uk.close
      ok.close
      return users
   end

   #
   ######################################################################################
   # exec_wmi - Exec a WMI cmd and return the output
   ######################################################################################
   #
   def exec_wmi(cmd, sleepTime=2, takeTwo=false)
      tmpOut = ''
      wmicPID = nil
      done=false
      wmicOut = @session.fs.file.expand_path("%TEMP%") + "\\"+ sprintf("%.5d",rand(100000))

      p = @session.sys.process.execute("cmd.exe /c wmic /append:#{wmicOut} #{cmd}", nil, {'Hidden' => true})
      wmicPID = p.pid
      sleep(sleepTime)
      while !done
         done = true
         @session.sys.process.get_processes.each do |pl|
            print "."
            STDOUT.flush
            done = false if pl['pid'] == wmicPID
         end
      end
      print "!\n"
      STDOUT.flush
      p.close
     
      p = @session.sys.process.execute("cmd.exe /c type #{wmicOut}", nil, {'Hidden' => 'true','Channelized' => true})
      while(pOut = p.channel.read)
         print "."
         STDOUT.flush
         tmpOut << pOut
      end
      print "!\n"
      STDOUT.flush
      p.channel.close
      p.close

      @session.fs.file.rm(wmicOut)
      #
      # when you exec wmic the very first time on a system, it seems the cmd doesn't run b/c wmic is configuring/installing or something...
      #
      if tmpOut.strip == "" && !takeTwo
         @logger.lpStatus("   No output from wmic...  maybe this was the first ever run?  Executing one more time...")
         tmpOut = exec_wmi(cmd, 2, true)
      end
      return tmpOut
   end     

   #
   ######################################################################################
   # exec_cmd - take in a string to exec w/ cmd.exe /c, and exec it; this is only intended for fire and forget cmds, where the output isn't needed to make decisions
   ######################################################################################
   #
   def exec_cmd(cmdStr="")
      return if cmdStr == ""
      cmdOut=""
      @logger.lpStatus("   Executing cmd: #{cmdStr}")
      p = @session.sys.process.execute("cmd.exe", "/c #{cmdStr}", {'Hidden' => 'true', 'Channelized' => 'true'})
      done=false
      tmpPID = p.pid
      sleep(2)
      while !done
         done = true
         @session.sys.process.get_processes.each do |pl|
            print "."
            STDOUT.flush
            done = false if pl['pid'] == tmpPID
         end
      end
      print "!\n"
      STDOUT.flush
      while (o=p.channel.read)
         cmdOut<<o
      end
      p.channel.close
      p.close
      @logger.lpStatus("   Cmd output: #{cmdOut}")
   end

   # 
   ######################################################################################
   # find_svc_dll - Given a service name, read the registry and return the path to the associated service DLL
   ######################################################################################
   #
   def find_svc_dll(svcName)
      svcDLL=""
      begin
         #
         # tx to Andre Muscat for explaining svchost n svcdll info on gfi.com
         #
         tmp=@session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\#{svcName}\\Parameters")
         svcDLL=tmp.query_value("ServiceDll").query().to_s.strip
         tmp.close
      rescue ::Exception => e
         @logger.lpError("ERROR: System.find_svc_dll: svcName=#{svcName}; #{e.class} - #{e}")
         svcDLL=""
      ensure
         return svcDLL
      end
   end

   #
   ######################################################################################
   # find_clsid_dll - Given a CLSID, read the registry and return the path to the associated DLL
   ######################################################################################
   #
   def find_clsid_dll(clsid)
      svcDLL=""
      begin
         tmp=@session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SOFTWARE\\Classes\\CLSID\\#{clsid}\\InprocServer32")
         svcDLL=tmp.query_value("").query().to_s.strip
         tmp.close
      rescue Rex::Post::Meterpreter::RequestError
         if clsid =~ /02D4B3F1-FD88-11D1-960D-00805FC79235/
            svcDLL="" # GIUD for COM+ System Application has no entry in the registry apparently
         else
            @logger.lpError("WARNING: System.find_clsid_dll: Unable to locate the dllhost.exe processID CLSID #{clsid} in HKLM\\SOFTWARE\\Classess\\CLSID\\")
            svcDLL=""
         end
      rescue ::Exception => e
         @logger.lpError("ERROR: System.find_clsid_dll: CLSID=#{clsid}; #{e.class} - #{e}")
         svcDLL=""
      ensure
         return svcDLL
      end
   end

   #
   ######################################################################################
   # imgDumper - Given a base addr, the base addr of the next img, and a process handle... dump the mem
   ######################################################################################
   #
   def imgDumper(base, nextBase, pimg)
      imgDump=''
      begin
         #
         # while we haven't hit the addr of the next img
         #
         while base < nextBase
            print "."
            STDOUT.flush
            #
            # query so we can get the region size, then read the mem if it's not unallocated
            #
            q=pimg.memory.query(base)
            imgDump << pimg.memory.read(base, q['RegionSize']) if !(q['Available'])
            base+=q['RegionSize']
         end
         print "!\n"
         STDOUT.flush
      rescue Rex::Post::Meterpreter::RequestError => re
         if (re.to_s =~ /stdapi_sys_process_memory_read: Operation failed: 998/)
            @logger.lpError("WARNING: imgDumper: Failed to read mem...")
         else
            @logger.lpError("ERROR: imgDumper (1): #{e.class} - #{e}; returning nil")
            return nil
         end
      rescue ::Exception => e
         @logger.lpError("ERROR: imgDumper (0): #{e.class} - #{e}; returning nil")
         return nil
      end
      imgDump
   end

   #
   ######################################################################################
   # netListStub - exec a remote cmd, read the channelized output, record it and display it
   ######################################################################################
   #
   def netListStub(cmd=nil, arg=nil, name=nil)
      tmpout=""
      @logger.lpGood("   Gathering info from #{name} (#{cmd} #{arg}):")
      p=@session.sys.process.execute("#{cmd}", "#{arg}", {'Hidden' => 'true','Channelized' => true})
      while (o=p.channel.read)
         tmpout<<o
      end
      p.channel.close
      p.close
      @logger.gatherData("#{name}", tmpout)
      @logger.lpGood(tmpout)
   end

   #
   ######################################################################################
   # msf_sys_log - a fallback log function to gather what data is possible when the win7/admin wmic ntevent bug is encountered...
   ######################################################################################
   #
   def msf_sys_log()
      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'   => "Application Log",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'Num', 'Generated', 'Written', 'Event ID', 'Type', 'Category', 'Strings', 'Data' ] )
      @logger.lpStatus("   Reading Application Log...")
      alog = @session.sys.eventlog.open("Application")
      alog.each_forwards do |l|
         print "."
         STDOUT.flush
         tbl << [ l.num, l.generated, l.written, l.eventid, l.type, l.category, l.strings, l.data.to_s ]
      end
      alog.close
      print "!\n"
      STDOUT.flush
      @logger.gatherData("app_log", tbl.to_csv)
      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'   => "Security Log",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'Num', 'Generated', 'Written', 'Event ID', 'Type', 'Category', 'Strings', 'Data' ] )
      @logger.lpStatus("   Reading Security Log...")
      seclog = @session.sys.eventlog.open("Security")
      seclog.each_forwards do |l|
         print "."
         STDOUT.flush
         tbl << [ l.num, l.generated, l.written, l.eventid, l.type, l.category, l.strings, l.data.to_s ]
      end
      seclog.close
      print "!\n"
      STDOUT.flush
      @logger.gatherData("sec_log", tbl.to_csv)
      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'   => "System Log",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'Num', 'Generated', 'Written', 'Event ID', 'Type', 'Category', 'Strings', 'Data' ] )
      @logger.lpStatus("   Reading System Log...")
      slog = @session.sys.eventlog.open("System")
      slog.each_forwards do |l|
         print "."
         STDOUT.flush
         tbl << [ l.num, l.generated, l.written, l.eventid, l.type, l.category, l.strings, l.data.to_s ]
      end
      slog.close
      print "!\n"
      STDOUT.flush
      @logger.gatherData("sys_log", tbl.to_csv)
   end


 public

   #
   ######################################################################################
   # system_info - gather & output general info about the system
   ######################################################################################
   #
   def system_info()
      begin
         tbl = Msf::Ui::Console::Table.new(
                  Msf::Ui::Console::Table::Style::Default,
                  'Header'  => "System Info",
                  'Prefix'  => "\n",
                  'Postfix' => "\n",
                  'Columns' => [ 'Info', 'Value(s)' ])

         tbl << [ "OS Version", "#{@session.sys.config.sysinfo['OS']}" ]
         tbl << [ "Architecture", "#{@session.sys.config.sysinfo['Architecture']}" ]
         tbl << [ "Language", "#{@session.sys.config.sysinfo['System Language']}" ]

         luStr=""
         localUsers = enum_local_users
         if localUsers
            localUsers.keys.sort{|a,b| a<=>b}.each do |rid|
               luStr += "#{localUsers[rid][:Name]} (ID: #{rid}); "
            end
            luStr[/; $/] = ""
            tbl << [ "Local Users", "#{luStr}" ]
         end

         #
         # tx carlos
         #
         auStr = ""
         username = ''
         keyNfo = @session.sys.registry.open_key(HKEY_USERS, "")
         keyNfo.enum_key.each do |key|
            username = ''
            case key
            when "S-1-5-18"
               username = "SYSTEM"
            when "S-1-5-19"
               username = "Local Service"
            when "S-1-5-20"
               username = "Network Service"
            else
               if key =~ /S-1-5-21-\d*-\d*-\d*-\d*$/
                  begin
                     os = @session.sys.config.sysinfo['OS']
                     cuName = @session.sys.registry.open_key(HKEY_USERS, "#{key}\\Volatile Environment")
                     if os =~ /(Windows 7|2008|Vista)/
                        username = cuName.query_value("USERNAME").query().to_s
                     elsif os =~ /(2000|NET|XP)/
                        appdata_var = cuName.query_value("APPDATA").query()
                        if appdata_var =~ /^\w\:\D*\\(\D*)\\\D*$/
                           username = appdata_var.scan(/^\w\:\D*\\(\D*)\\\D*$/)[0][0]
                        end
                     end
                     cuName.close
                  rescue Rex::Post::Meterpreter::RequestError => re
                     username = "***ERROR READING KEY: #{key}***"
                  end
               end
            end
            if username != ''
               auStr += "#{username}; "
            end
         end
         keyNfo.close
         if auStr != ""
            auStr[/; $/]=""
         end
         tbl << [ "Active Users", "#{auStr}" ]
       
         @logger.gatherData("system_info", tbl.to_csv)
         if (tbl.rows.length > @logger.max_display_lines)
            @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
         else
            @logger.lpGood(tbl.to_s)
         end

      rescue ::Exception => e
         @logger.lpError("System.system-info (0): #{e.class} - #{e}")
         raise Rex::Script::Completed
      end
   end

   #
   ######################################################################################
   # startup_items - gather info on startup items from wmic, and hash them if requested
   ######################################################################################
   #
   def startup_items(hash=false, wlArr=[])
      if @session.sys.config.sysinfo['OS'] =~ /Windows 7/ && @logger.is_system == false
         @logger.lpError("   ERROR: Unable to enumerate startup items on >= Win7 without SYSTEM perms...")
         return
      end
      begin
         tbl = Msf::Ui::Console::Table.new(
                  Msf::Ui::Console::Table::Style::Default,
                  'Header'  => "System Info",
                  'Prefix'  => "\n",
                  'Postfix' => "\n",
                  'Columns' => [ 'Caption', 'Command', 'Description', 'Location', 'SettingID', 'User', 'MD5' ])

         tmpout = exec_wmi("startup list full")

         item = []
         cmdPath = ""
         tmpout.each_line do |line|
            print "."
            STDOUT.flush
            if line =~ /=/
               line.chomp!
               case line
               when /^Caption=/
                  #
                  # this is the first line of a startup listing
                  #
                  line[/Caption=/]=""
                  item=[]
                  item.push(line)
               when /^User=/
                  #
                  # this is the last line of a startup listing, so store the val and perform hashing if needed
                  #
                  line[/User=/]=""
                  item.push(line)
                  hashVal=""
                  if hash
                    hashVal=@fs.quickHash(cmdPath)
                  end
                  item.push(hashVal)
                  if hash && wlArr.length > 0
                     next if wlArr.include?(hashVal.upcase)
                  end
                  tbl << item
               when /^Command=/
                  #
                  # pull out any cmd params, and store the cmd path for later hashing...
                  #
                  line[/Command=/]=""
                  item.push(line)
                  cmdPath=line.gsub('"', '').gsub(/\.exe\ .*/i, '.exe')
               else
                  #
                  # otherwise carve out everything preceeding the first equal sign (inclusive)
                  #
                  line[0..line.index("=")]=""
                  item.push(line)
               end
            end
         end
         print "!\n"
         STDOUT.flush
         @logger.gatherData("startup_items", tbl.to_csv)
         if (tbl.rows.length > @logger.max_display_lines)
            @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
         else
            @logger.lpGood(tbl.to_s)
         end
      rescue ::Exception => e
         @logger.lpError("System.startup_items (0): #{e.class} - #{e}")
         raise Rex::Script::Completed
      end
   end

   # 
   ######################################################################################
   # process_list - process listing w/ PID, name, exe path, hash, etc
   ######################################################################################
   #
   def process_list(hash=false, wlArr=[]) 

      if @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM will limit the ability to enumerate process information")
      end

      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'  => "Process Listing",
               'Prefix'  => "\n",
               'Postfix' => "\n",
               'Columns' => [ 'PID', 'Parent', 'Name', 'Path', 'Session', 'User', 'Arch', 'MD5' ])

      @session.sys.process.get_processes().each do |p|
         tmpHash = ''
         print "."
         STDOUT.flush
         #
         # some of the path values returned are quirky, so smooth em out...
         #
         if p['path'] =~ /^\\SystemRoot\\/
            p['path']["\\SystemRoot"] = "%SYSTEMROOT%"
         elsif p['path'] =~ /^\\??\\/
            p['path']["\\??\\"] = ""
         end
         if hash && p['path'] != ""
            tmpHash = @fs.quickHash(p['path'])
            if tmpHash =~ /access denied/i
               tmpHash = "Access Denied"
            end
         end
         p["Hash"] = tmpHash
         if hash && wlArr.length > 0
            next if wlArr.include?(tmpHash.upcase)
         end
         tbl << p.values
      end
      print "!\n"
      STDOUT.flush
      @logger.gatherData("process_list", tbl.to_csv)
      if (tbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(tbl.to_s)
      end
   end

   #
   ######################################################################################
   # service_list - service listing w/ file path, svc arguments, signed or not, hash, run state, start state, etc
   ######################################################################################
   #
   def service_list(hash=false, wlArr=[])
      if @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM will limit the ability to enumerate service information")
      end
      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'  => "Service Listing",
               'Prefix'  => "\n",
               'Postfix' => "\n",
               'Columns' => [ 'AcceptPause', 'AcceptStop', 'Caption', 'CheckPoint', 'CreationClassName', 'Description', 'DesktopInteract', 'DisplayName', 
                              'ErrorControl', 'ExitCode', 'InstallDate', 'Name', 'PathName', 'PID', 'SvcSpecificErrorCode', 'SvcType', 'Started',
                              'StartMode', 'StartName', 'State', 'Status', 'SysCreationClassName', 'SysName', 'TagID', 'WaitHint', 'Service MD5',
                              'ServiceDLL', 'ServiceDLL MD5' ])
      tmpRec=[]
      tmpHash=""
      svcName=""
      svcDLL=""
      svcDLLHash=""
      skip=false
      nfo = exec_wmi("service list full")
      nfo.each_line do |line|
         skip=false
         print "."
         STDOUT.flush
         if line != nil && line.strip() != ""
            line.strip!
            lineVal="#{line}"
            lineVal[0..lineVal.index("=")]=""
            case line
            when /^AcceptPause=/
               #
               # This is the first line of a wmic service listing
               #
               tmpRec=[]
               tmpRec.push(lineVal)
            when /^WaitHint=/
               #
               # This is the last line of a wmic service listing so record WaitHint, the path hash, and svc dll foo...
               #
               tmpRec.push(lineVal)
               tmpRec.push(tmpHash)
               tmpRec.push(svcDLL)
               tmpRec.push(svcDLLHash)
               if hash && wlArr.length > 0
                  if svcDLLHash != ""
                     if wlArr.include?(tmpHash.upcase) && wlArr.include?(svcDLLHash.upcase)
                        skip = true
                     end
                  else
                     skip = true if wlArr.include?(tmpHash.upcase)
                  end
               end
               if skip == false
                  tbl << tmpRec
               end
               tmpHash=""
               svcName=""
               svcDLL=""
               svcDLLHash=""
            when /^PathName=/
               #
               # with SVCHOST and DLLHOST paths we have to clean them up a bit...
               #
               if lineVal =~ /svchost\.exe -k /i || lineVal =~ /svchost -k /i
                  #
                  # for svchost, drop the params (so we can hash it), and then append .exe if needed...
                  #
                  hashVal="#{lineVal}"
                  hashVal[/ -k .*/]=""
                  if hashVal =~ /svchost$/i
                     hashVal="#{hashVal}.exe"
                  end
                  svcDLL=find_svc_dll(svcName)
               elsif lineVal =~ /dllhost\.exe \/Processid:/i || lineVal =~ /dllhost \/Processid:/i
                  clsid="#{lineVal}"
                  clsid[/.*\/Processid:/]=""
                  svcDLL=find_clsid_dll(clsid)
                  hashVal="#{lineVal}"
                  hashVal[/ \/Processid:.*/]=""
               else
                  hashVal=lineVal
               end
               tmpHash=""
               if hash && hashVal != ""
                  tmpHash=@fs.quickHash(hashVal)
                  if svcDLL != ""
                     svcDLLHash=@fs.quickHash(svcDLL)
                  end
               end
               tmpRec.push(lineVal)
            when /^Name=/
               #
               # store this so we can look it up later if it's an svchost service...
               #
               svcName=lineVal
               tmpRec.push(lineVal)
            else
               tmpRec.push(lineVal)
            end
         end
      end
      print "!\n"
      STDOUT.flush
      @logger.gatherData("service_list", tbl.to_csv)
      if (tbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(tbl.to_s)
      end
   end
   
   #
   ######################################################################################
   # driver_list - wmic driver listing w/ path, desc, hash, etc
   ######################################################################################
   #
   def driver_list(hash=false, wlArr=[])

      if hash && @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM will limit the ability to hash drivers on >= Win7")
      end

      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
	       'Header'   => "Driver Listing",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'AcceptPause', 'AcceptStop', 'Description', 'DesktopInteract', 'DisplayName', 'ErrorControl', 'ExitCode', 'InstallDate',
                               'Name', 'Path', 'SvcSpecificExitCode', 'ServiceType', 'Started', 'StartMode', 'StartName', 'State', 'Status',
                               'SystemName', 'TagID', 'MD5' ] )

      tmpRec=[]
      tmpHash=""

      nfo = exec_wmi("sysdriver list full")
      nfo.each_line do |line|
         print "."
         STDOUT.flush
         if line != nil && line.strip() != ""
            line.strip!()
            lineVal="#{line}"
            lineVal[0..lineVal.index("=")]=""
            case line
            when /^AcceptPause=/
               #
               # This is the first line of a wmic driver listing
               #
               tmpRec=[]
               tmpRec.push(lineVal)
            when /^TagId=/
               #
               # This is the last line of a wmic driver listing, so record it and the hash value...
               #
               tmpRec.push(lineVal)
               tmpRec.push(tmpHash)
               if hash && wlArr.length > 0
                  next if wlArr.include?(tmpHash.upcase)
               end
               tbl << tmpRec
            when /^PathName=/
               #
               # Hash this value if we're hashing, and hold onto it for later, then store the path value...
               #
               tmpHash=""
               if hash && lineVal != "" && lineVal != nil
                  tmpHash=@fs.quickHash(lineVal)
               end
               tmpRec.push(lineVal)
            else
               tmpRec.push(lineVal)
            end
         end
      end
      print "!\n"
      STDOUT.flush
      @logger.gatherData("driver_list", tbl.to_csv)
      if (tbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(tbl.to_s)
      end
   end

   #
   ######################################################################################
   # system_log - read log info from wmic
   ######################################################################################
   #
   def system_log(tail=false)

      tmpLog={}
      logs=[]
      os=@session.sys.config.sysinfo['OS']
      @logger.lpStatus("   Pulling log information from WMIC... (this can take a while)")
      rawLogData = exec_wmi('ntevent list full /format:value')
      if rawLogData.strip == "" && os =~ /Windows 7/ && @session.sys.config.getuid =~ /SYSTEM/
         @logger.lpError("   WMIC returned no data and the current host is Win7 running as System.  Executing 'wmic ntevent list' as administrator in Win7 can result in an error condition where no data is returned.  This may or may not be related to a known bug in Win7/2k8 concerning eventID 4739 (http://support.microsoft.com/kb/2536111).  Falling back on MSF event log parsing...")
         msf_sys_log()
         return
      elsif rawLogData.strip == ""
         @logger.lpError("   ERROR: No log data returned...")
         return
      end
      #
      # need to pre-parse to catch logs that are longer than a single line... other /format options (ie: csv) have other issues...
      #
      @logger.lpStatus("   Pre-Parsing log information...")
      #
      # split the data into an array of lines
      #
      z=rawLogData.split("\n")
      #
      # get rid of all the blank lines
      #
      z.each do |zed|
         zed.strip!
      end
      z.delete("")
      #
      # make note of our curr array length
      #
      zMax=z.length-1
      #
      # for each line w/ data
      #
      for i in (0..z.length-1)
         #
         # check if we're past the end of the array (since we're reducing the size as we go)
         #
         break if (i > zMax)
         #
         # if the line doesn't contain a known '^foo=' statement, that means we need to combine it w/ the line before 
         #
         if (z[i] !~ /^Category=/i) &&       (z[i] !~ /^CategoryString=/i) &&   (z[i] !~ /^ComputerName=/i) &&
            (z[i] !~ /^Data=/i) &&           (z[i] !~ /^EventCode=/i) &&        (z[i] !~ /^EventIdentifier=/i) &&
            (z[i] !~ /^EventType=/i) &&      (z[i] !~ /^InsertionStrings=/i) && (z[i] !~ /^Logfile=/i) &&
            (z[i] !~ /^Message=/i) &&        (z[i] !~ /^RecordNumber=/i) &&     (z[i] !~ /^SourceName=/i) &&
            (z[i] !~ /^TimeGenerated=/i) &&  (z[i] !~ /^TimeWritten=/i) &&      (z[i] !~ /^Type=/i) && 
            (z[i] !~ /^User=/i)
            #
            # then append the line value to the last line while deleting that element from the array
            #
            z[i-1]+=z.delete_at(i)
            #
            # decrement zMax since the array is shorter
            #
            zMax-=1
            #
            # now 'redo' b/c we need to reprocess w/ this 'i' value since we deleted an element
            #
            redo
         end
      end
      #
      # now put the log lines back together
      #
      newLogData=z.join("\n")
      #
      # and get back to parsing them...
      #
      @logger.lpStatus("   Parsing log information...")
      #
      # check for a lastLogTime val...  for use when tailing logs...
      #
      lastLogTime = @logger.getLastSysLogTime()
      lastLogTime.strip! if lastLogTime
      @logger.lpStatus("   Found lastLogTime: #{lastLogTime}") if lastLogTime

      newLogData.each_line do |logLine|
         print "."
         STDOUT.flush
         key=""
         val=""
         #
         # the first line of a log entry
         #
         if logLine =~ /^Category=/
            #
            # initialize the log hash, since this is a new log entry
            #
            tmpLog={}
            #
            # record the data into the hash, keeping in mind there might be equal signs in the data
            #
            tmpArr=logLine.split("=")
            key=tmpArr[0]
            tmpArr.shift
            val=tmpArr.join("=")
            tmpLog["#{key}"]=val.strip
         #
         # the last line of a log entry
         #
         elsif logLine =~ /^User=/
            tmpArr=logLine.split("=")
            key=tmpArr[0]
            tmpArr.shift
            val=tmpArr.join("=")
            tmpLog["#{key}"]=val.strip
            #
            # record the completed log hash into the log array
            #
            logs.push(tmpLog)
         #
         # for any other line, just record the data
         #
         else
            tmpArr=logLine.split("=")
            key=tmpArr[0]
            tmpArr.shift
            val=tmpArr.join("=")
            tmpLog["#{key}"]=val.strip
         end
      end

      print "!\n"
      STDOUT.flush

      # 
      # you can't really sort by RecordNumber, b/c there are dupes... so better to just tail off the generation time... (?)
      #
      logs=logs.sort_by { |l| l['TimeGenerated'] }

      #
      # if we have a lastLogTime val, then pull out everything before it...
      #
      if tail && lastLogTime
         @logger.lpStatus("   Trimming log entries for logtail...")
         lMax=logs.length-1          
         for i in (0..logs.length-1)
            break if (i > lMax)
            if logs[i]['TimeGenerated'] < lastLogTime
               logs.delete_at(i)
               lMax-=1
               redo
            end
         end
      elsif tail && !lastLogTime
         @logger.lpStatus("   Running logtail, but no valid lastLogTime found, so returning full dataset...")
      end

      #
      # record the new lastLogTime val
      #
      lastLogTime=logs[logs.length-1]['TimeGenerated'].strip
      @logger.setLastSysLogTime(lastLogTime)
      @logger.lpStatus("   The new lastLogTime is #{lastLogTime}")

      #
      # record the data into two tables... one for recording all the data, and one for displaying to the operator
      #
      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'   => "System Log",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'Category', 'CategoryString', 'ComputerName', 'Data',  'EventCode', 'EventIdentifier', 
                               'EventType', 'InsertionStrings', 'LogFile', 'Message', 'RecordNumber', 'SourceName',
                               'TimeGenerated', 'TimeWritten', 'Type', 'User'])

      displayTbl = Msf::Ui::Console::Table.new(
                     Msf::Ui::Console::Table::Style::Default,
                    'Header'   => "System Log (Display Format)",
                    'Prefix'   => "\n",
                    'Postfix'  => "\n",
                    'Columns'  => [ 'LogFile', 'TimeGenerated', 'EventCode', 'EventID', 'Message'])

      logs.each do |l|
         tbl << l.values
         displayTbl << [ l['Logfile'], l['TimeGenerated'], l['EventCode'], l['EventIdentifier'], l['Message'] ]
      end

      @logger.gatherData("system_log", tbl.to_csv)
      if (displayTbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(displayTbl.to_s)
      end

   end

   #
   ######################################################################################
   # job_list - scheduled job listing read from wmic
   ######################################################################################
   #
   def job_list()
      if @session.sys.config.sysinfo['OS'] =~ /Windows 7/ && @logger.is_system == false
         @logger.lpError("   ERROR: Unable to enumerate schedules jobs on >= Win7 without SYSTEM perms...")
         return
      end

      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header'   => "Job Listing",
               'Prefix'   => "\n",
               'Postfix'  => "\n",
               'Columns'  => [ 'Command', 'DaysOfMonth', 'DaysOfWeek', 'Description', 'ElapsedTime', 'InstallDate', 'InteractWithDesktop',
                               'JobID', 'JobStatus', 'Name', 'Notify', 'Owner', 'Priority', 'RunRepeatedly', 'StartTime', 'Status', 
                               'TimeSubmitted', 'UntilTime' ] )
      tmpRec = []
      nfo = exec_wmi("job list full")
      nfo.each_line do |line|
         if line != nil && line.strip() != ""
            line.strip!()
            lineVal="#{line}"
            lineVal[0..lineVal.index("=")]=""
            case line
            when /^Command=/
               #
               # first line of a job listing
               #
               tmpRec = []
               tmpRec.push(lineVal)
            when /^UntilTime=/
               #
               # last line of a job listing
               #
               tmpRec.push(lineVal)
               tbl << tmpRec
            else
               tmpRec.push(lineVal)
            end
         end
      end
      @logger.gatherData("job_list", tbl.to_csv)
      if (tbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(tbl.to_s)
      end
   end

   #
   ######################################################################################
   # net_list - Recent network information (default netstat and arp info), plus other net related info
   ######################################################################################
   #
   def net_list(netstat=true, arp=true, route=false, hosts=false, ipconfig=false)
      if (netstat==false && arp==false && route==false && hosts==false && ipconfig==false)
         @logger.lpError("   WARNING: No operation given... n0p")
      else
         netListStub("netstat.exe", "-nao", "netstat") if netstat
         netListStub("arp.exe", "-a", "arp") if arp
         netListStub("route.exe", "print", "route") if route
         netListStub("cmd.exe", "/c type %SYSTEMROOT%\\system32\\drivers\\etc\\hosts", "hosts") if hosts
         netListStub("ipconfig.exe", "/all", "ipconfig") if ipconfig
      end
   end

   #
   ######################################################################################
   # restore_point_list - find restore points and list files within them
   ######################################################################################
   #
   def restore_point_list(bruteMax=5)

      if @logger.is_system == false
         @logger.lpError("   ERROR: restore_point_list(): Running as #{@session.sys.config.getuid}, but need SYSTEM... exiting...")
         return
      end
      
      os=@session.sys.config.sysinfo['OS']
      if os =~ /Windows XP/
         rPnt=[]
         rpDir=[]
         
         #
         # check contents of %SYSTEMDRIVE%\\System Volume Information\\ for a folder starting w/ _restore
         #
         @logger.lpStatus("   Searching for restore directories...")
         rpPath=@session.fs.file.expand_path("%SYSTEMDRIVE%\\System Volume Information\\")
         @session.fs.dir.foreach(rpPath) do |f|
            next if f =~ /^(\.|\.\.)$/
            fullpath = rpPath + '\\' + f
            if @session.fs.file.stat(fullpath).directory? && f =~ /_restore/
               rpDir.push(fullpath)
            end
         end

         if rpDir.length == 0
            @logger.lpStatus("   No _restore directory found in #{rpPath}...")
         else
            #
            # there should only ever be one dir w/ restore points... but just in case...?
            #
            @logger.lpStatus("   Enumerating restore point directories...")
            rpDir.each do |d|
               @session.fs.dir.foreach(d) do |x|
                  next if x =~ /^(\.||\.\.)$/
                  fullpath = d + '\\' + x
                  if @session.fs.file.stat(fullpath).directory? && x =~ /^RP\d+/
                     rPnt.push(fullpath)
                  end
               end
            end
            #
            # for each restore point directory...
            #
            if rPnt.length == 0
               @logger.lpStatus("   No restore points found...")
            else
               rPnt.each do |r|

                  next if r.strip==""
                  changelog=false
                  snapshot=false

                  #
                  # find change.log files if they exist
                  #
                  clogs=[]
                  @session.fs.dir.foreach(r) do |x|
                     if x =~ /change\.log/
                        clogs.push(r + "\\" + x)
                     end
                  end
                  changelog = true if clogs != []

                  #
                  # find registry snapshots if they exist
                  #
                  if (@session.fs.file.exists?(r + "\\snapshot") == true)
                     if (@session.fs.file.stat(r + "\\snapshot").directory? == true)
                        snapshot=true
                     end
                  end

                  if !changelog and !snapshot
                     @session.lpError("   ERROR: No changelog and no snapshot, skipping...")
                     next
                  end

                  #
                  # record the restore point number
                  #
                  rpNum=r[/RP\d+/]

                  #
                  # guestimate RP time based on change.log stat info
                  #
                  if changelog
                     rpTime=Time.at(@session.fs.file.stat(clogs[0]).stathash["st_ctime"]).localtime("-00:00")
                  else
                     rpTime=Time.at(@session.fs.file.stat(r + "\\snapshot").stathash["st_ctime"]).localtime("-00:00")
                  end

                  #
                  # prep the output table
                  #
                  tbl = Msf::Ui::Console::Table.new(
                           Msf::Ui::Console::Table::Style::Default,
                          'Header' => "Restore Point Listing for #{rpNum} (created around #{rpTime})",
                          'Prefix' => "\n",
                          'Postfix' => "\n",
                          'Columns' => [ 'File Name', 'Orig Name', 'Size', 'Hash' ] )
                  
                  if changelog
                     clogs.each do |cl|
                        @logger.lpStatus("   Parsing #{cl[/change\.log\..*/i]} for #{rpNum}...")
                        #
                        # read the changelog file contents
                        #
                        rpFile=@session.fs.file.new(cl, 'r')
                        rpdata=""
                        until rpFile.eof?
                           rpdata << rpFile.read
                        end
                        rpFile.close
                        #
                        # parse the changelog to find the original filenames of the restore point files (there is probably a better way to do this)
                        #
                        rparr=rpdata.unpack('s*')
                        for i in (0..rparr.length-1)
                           #
                           # it looks like the ascii chars 0,34,0,5,0 delimit each mapping between the /A\d+.ext/ filename and orig filename
                           #
                           if rparr[i]==0 && rparr[i+1]==34 && rparr[i+2]==0 && rparr[i+3]==5 && rparr[i+4]==0
                              aName=origName=""
                              #
                              # we know how many chars to read, b/c filename is always a fixed len
                              #
                              rparr[i+5..i+16].each do |z|
                                 aName+=z.chr
                              end
                              #
                              # now we work our way backward to read the orig filename
                              #
                              newI=i
                              while newI > 1
                                 #
                                 # it looks like the ascii chars 0,3,0 preceed the begining of the orig filename...
                                 #
                                 if rparr[newI]==0 && rparr[newI-1]==3 && rparr[newI-2]==0
                                    rparr[newI..i-1].each do |z|
                                       origName+=z.chr
                                    end
                                    origName=@session.fs.file.expand_path("%SYSTEMDRIVE%") + origName
                                    break
                                 else
                                    newI-=1
                                 end
                              end
                              if newI == 1
                                 @logger.lpError("   ERROR: failed to read the change.log file.... giving up!")
                                 return
                              else
                                 #
                                 # we should have the A-name and orig name, so stat the file and record it
                                 #
                                 fSize=@session.fs.file.stat(r + '\\' + aName).stathash['st_size']
                                 tbl << [aName, origName, fSize, @fs.quickHash("#{r}\\#{aName}")]
                              end
                           end
                        end
                     end
                  end
                  #
                  # registry snapshot names are fairly self-explanatory
                  #
                  if snapshot
                     @session.fs.dir.foreach(r + "\\snapshot\\") do |x|
                        if x =~ /^_registry_/i
                           fSize=@session.fs.file.stat(r + '\\snapshot\\' + x).stathash['st_size']
                           tbl << [x, "", fSize, ""]
                        end
                     end
                  end

                  if tbl.rows.length==0
                     @logger.lpStatus("   No data found...")
                  else
                     @logger.gatherData("restore_point_list_#{}", tbl.to_csv)
                     if (tbl.rows.length > @logger.max_display_lines)
                        @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
                     else
                        @logger.lpGood(tbl.to_s)
                     end
                  end
               end
            end
         end

      #
      # vista/win7 makes this interesting/difficult... tx to securitybraindump.blogspot.com for the good info!
      #
      elsif os =~ /Windows 7/ #|| os =~ /Vista/i
         
         scv=[]
         vssOutput=""
         p=@session.sys.process.execute("cmd.exe", "/c vssadmin.exe list shadows /for=%SYSTEMDRIVE%", {'Hidden' => true, 'Channelized' => true})
         #p=@session.sys.process.execute("c:\\windows\\system32\\vssadmin.exe", "list shadows", {'Hidden' => true, 'Channelized' => true})
         while v=p.channel.read
            vssOutput<<v
         end
         p.channel.close
         p.close

         # 
         # seems like vssadmin doesn't like to run via meterpreter after getsystem...?  sometimes?
         #
         if vssOutput =~ /Error/
            @logger.lpStatus("   Unable to execute VSSAdmin to list shadow volumes, so attempting brute force of #{bruteMax} on \\GLOBALROOT\\Device\\...")
            for i in (1..bruteMax)
               scv.push("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{i}")
            end
         else
            vssOutput.each_line do |l|
               if l =~ /Shadow Copy Volume: /
                  l[/.*Shadow Copy Volume: /]=""
                  scv.push(l.strip)
               end
            end
         end

         scv.each do |s|
           
            #
            # create a symlink dir to the shadow copy volume
            #
            linkOut=""
            tmpLink = @session.fs.file.expand_path("%TEMP%") + "\\" + sprintf("%.5d",rand(100000))
            @logger.lpStatus("   Linking #{s} <==> #{tmpLink}")
            p=@session.sys.process.execute("cmd.exe", "/c mklink /d #{tmpLink} #{s}\\", {'Hidden' => true, 'Channelized' => true})
	    while v=p.channel.read
               linkOut<<v
            end
            p.channel.close
            p.close

            #
            # check if the link worked
            #
            if linkOut =~ /symbolic link created for/
               @logger.lpStatus("   Link created...") 

               tbl = Msf::Ui::Console::Table.new(
                        Msf::Ui::Console::Table::Style::Default,
                        'Header' => "Restore Point Listing for: #{s}",
                        'Prefix' => "\n",
                        'Postfix' => "\n",
                        'Columns' => [ 'Path', 'Name', 'Size', 'Hash' ] )
               #
               # enum the contents
               # 
               @logger.lpStatus("   Searching... (be patient, this can take a *while*)")
               begin
                  @session.fs.file.search("#{tmpLink}\\").each do |f|
                     print "."
                     STDOUT.flush
                     tbl << [ f.path, f.name, f.size, @fs.quickHash(f.path) ]
                  end
                  print "!\n"
                  STDOUT.flush
               rescue Rex::Post::Meterpreter::RequestError => re
                  @logger.lpStatus("   Looks like there is no data in this symlink (are you brute forcing shadow volumes?)...")
               end

               if tbl.rows.length == 0
                  @logger.lpStatus("   No data found in #{s.strip}")
               else
                  @logger.gatherData("restore_point_list_#{s}", tbl.to_csv)
                  if (tbl.rows.length > @logger.max_display_lines)
                     @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
                  else
                     @logger.lpGood(tbl.to_s)
                  end
               end
  
               #
               # delete the symlink
               #
               @session.lpStatus("   Cleaning up symlink...")
               linkOut=""
               p=@session.sys.process.execute("cmd.exe", "/c rmdir #{tmpLink}", {'Hidden' => true, 'Channelized' => true})
               while v=p.channel.read
                  linkOut<<v
               end
               p.channel.close
               p.close
            else
               @logger.lpError("   Unable to create symlink for #{s}... moving on")
            end
         end  
      else
         @logger.lpError("   ERROR: restore_point_list(): The client OS (#{os}) is not supported...")
         return
      end

   end

   #
   ######################################################################################
   # process_mem_capture - read and record the process memory space for a given pid
   ######################################################################################
   #
   def process_mem_capture(pid=nil, dumpModules=false, dumpFull=false)
      imgs=[]
      #
      # using the real max vals (214741811/4294901759) throws exceptions, so we're using a slightly lower val that doesn't...
      #
      maxAppAddr=2147330000
      maxAppAddr=4294800000 if @session.platform =~ /win64/

      if @logger.is_system == false
         @logger.lpError("   ERROR: Unable to capture process memory without SYSTEM perms...")
         return
      end

      if !pid
         @logger.lpError("   No PID provided, nothing to capture... n0p")
         return
      else
         #
         # we prefer to open w/ ALL_ACCESS, but fall back to READ if we can't...
         #
         begin
            p=@session.sys.process.open(pid.to_i, PROCESS_ALL_ACCESS)
         rescue
            begin
               p=@session.sys.process.open(pid.to_i, PROCESS_READ)
            rescue ::Exception => e
               @logger.lpError("   ERROR: process_mem_capture (0): unable to open pid #{pid} with ALL_ACCESS or READ: #{e.class} - #{e}")
               raise Rex::Script::Completed
            end
         end
         #
         # here we're kinda assuming the main process will always have the lowest base addr, which appears true based on spot checks...
         #
         imgs=p.image.get_images.sort_by { |pimg| pimg['base'] }
         if dumpFull
            @logger.lpStatus("   Dumping PID #{pid} (#{p.name}) and image addr space as single file...")
            @logger.gatherBin("proc_mem_capture_#{p.name}_full_dump", imgDumper(0, maxAppAddr, p))
         elsif dumpModules
           for n in (0..imgs.length-1)
              @logger.lpStatus("   Dumping PID #{pid} (#{p.name}): image: #{imgs[n]['name']} (#{imgs[n]['path']})...")
              if (n != imgs.length-1)
                 @logger.gatherBin("proc_mem_capture_#{p.name}_imgpath_#{imgs[n]['path']}", imgDumper(imgs[n]['base'], imgs[n+1]['base'], p))
              else
                 @logger.lpError("WARNING: known bug capturing the final image...  size/md5 will not match LordPE, but img should only include some extra data at the tail")
                 @logger.gatherBin("proc_mem_capture_#{p.name}_imgpath_#{imgs[n]['path']}", imgDumper(imgs[n]['base'], maxAppAddr, p))
              end
           end
         else
            @logger.lpStatus("   Dumping PID #{pid} (#{p.name}): image: #{imgs[0]['name']} (#{imgs[0]['path']}) ...")
            @logger.gatherBin("proc_mem_capture_#{p.name}_imgpath_#{imgs[0]['path']}", imgDumper(imgs[0]['base'], imgs[1]['base'], p))
         end
      end
   end

   #
   ######################################################################################
   # registry_capture - just a wrapper for the REG cmd; simple n effective...
   ######################################################################################
   #
   def registry_capture(rootKey="", subKey="", hive=false)
 
      if @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM perms, so registry read access may be limited...")
      end

      tmpout=""
      tmpFile=""

      if !(rootKey=~/^HKLM$/i || rootKey=~/^HKCU$/i || rootKey=~/^HKCR$/i || rootKey=~/^HKU$/i || rootKey=~/^HKCC$/i)
         @logger.lpError("   ERROR: registry_list (0): invalid Root Key value (#{rootKey}); unable to proceed...")
      else

         if hive
            regCmd="reg save "
            regExt="hiv"
         else
            regCmd="reg export "
            regExt="reg"
         end

         tmpFile = @session.fs.file.expand_path("%TEMP%") + "\\" + sprintf("%.5d",rand(100000))
         if subKey == ""
            regCmd+="#{rootKey} #{tmpFile}"
         else
            regCmd+="#{rootKey}\\#{subKey} #{tmpFile}"
         end

         r = @session.sys.process.execute("cmd.exe /c #{regCmd}", nil, {'Hidden' => 'true','Channelized' => true})
         while(d = r.channel.read)
            tmpout << d
         end
         r.channel.close
         r.close

         if tmpout =~ /error/i
            @logger.lpError("   ERROR: registry_list (1): command execution reported an error (root:#{rootKey} sub:#{subKey}): #{tmpout}")
         elsif tmpout =~ /success/i
            regOutput = @session.fs.file.new(tmpFile, "r")
            regVal=""
            until regOutput.eof?
               regVal << regOutput.read
            end
            regOutput.close
            if subKey == ""
               skStr="full"
            else
               skStr=subKey
            end
            @logger.gatherBin("registry_list_#{rootKey}_#{skStr}.#{regExt}", regVal)            
            @session.sys.process.execute("cmd.exe /c del #{tmpFile}", nil, {'Hidden' => true})
         else
            @logger.lpError("   ERROR: registry_list (2): unknown response: #{tmpout}")
         end
      end
   end

   #
   ######################################################################################
   # isolate - keep a host from communicating via layer 2, layer 3, and/or dns
   ######################################################################################
   #
   def isolate(dns=false, layer3=false, layer2=false, undo=false)

      maxCmdLen=8100 # per kb830473, max cmd line len == 8191 for >= XP
      fakeARP="11-11-11-11-11-11"

      if @logger.is_system == false
         @logger.lpError("   ERROR: Unable to run effectively without SYSTEM... exiting :(")
         return
      end

      #
      # get the msf IP so we can make sure not to disrupt 
      #
      metIP=@session.tunnel_local.split(":")[0]
      @logger.lpStatus("   MSF IP is: #{metIP}")
      #
      # and the local ip
      #
      localIP=@session.tunnel_peer.split(":")[0]
      @logger.lpStatus("   Local IP is: #{localIP}")
      #
      # figure out the gateway (so we can exempt it)
      #
      localGate=""
      @session.net.config.each_route do |r|
         localGate = r.gateway if r.subnet == "0.0.0.0" && r.netmask == "0.0.0.0"
      end
      if localGate == ""
         @logger.lpError("   ERROR: isolate(): Unable to determine local gateway... quitting")
         return
      end
      #
      # to calc the network id to use it as a null ip, we need the subnet
      #
      localSubnet=""
      found=false # track if we can break out of the outter loop
      @session.net.config.each_interface do |i|
         #
         # each interface could have multiple ip addr
         #
         n=0 # counter for which interface we're on
         i.addrs.each do |x|
            if x == localIP
               localSubnet=i.netmasks[n]
               found=true
               break
            else
               n+=1
            end
         end
         break if found
      end
      if localSubnet == ""
         @logger.lpError("   ERROR: isolate(): unable to determine the subnet... quitting")
         return
      end
      #
      # convert the subnet mask into a bitmask so we can use RangeWalker
      #
      localBitmask=Rex::Socket.net2bitmask(localSubnet)
      @logger.lpStatus("   Local subnet is: #{localSubnet} (/#{localBitmask})")
      #
      # build the RangeWalker object and call next_ip to get the begining of the subnet, the network id...
      #
      rw=Rex::Socket::RangeWalker.new("#{localIP}/#{localBitmask}")
      nullIP=rw.next_ip
      @logger.lpStatus("   Calculated network-id for null IP is: #{nullIP}")
      
      if undo
         @logger.lpStatus("   Removing fake ARP entries...")
         #
         # read the current arp table
         #
         p = @session.sys.process.execute("arp.exe", "-a", {'Hidden' => true, 'Channelized' => true})
         arpInfo=""
         l2Undo=""
         while (pOut = p.channel.read)
            arpInfo << pOut
         end
         p.channel.close
         p.close
         #
         # if the line contains our fake arp, build a cmd string to delete it
         #
         arpInfo.each_line do |l|
            if l =~ /#{fakeARP}/
               l[/#{fakeARP}.*/] = ""
               l.strip!
               l2Undo += "arp -d #{l} && "
               if l2Undo.length > maxCmdLen
                  l2Undo[/&& $/]=""
                  exec_cmd(l2Undo)
                  l2Undo=""
               end
            end
         end
         if l2Undo != ""
            l2Undo[/ && $/]=""
            exec_cmd(l2Undo)
            l2Undo=""
         end
         #
         # if a route points to our null ip, delete it
         # 
         @logger.lpStatus("   Removing null routes...")
         l3Undo="route delete 0.0.0.0 mask 0.0.0.0 #{nullIP} && route delete #{metIP} && "
         @session.net.config.routes.each do |r|
            l3Undo += "route delete #{r.subnet} mask #{r.netmask} #{r.gateway} && " if "#{r.gateway}" == nullIP
         end
         l3Undo[/ && $/]=""
         exec_cmd(l3Undo)
         @logger.lpGood("   Complete!")
         return
      end     

      if dns
         #
         # start with the static arp for the null ip
         #
         cmdStr="arp -s #{nullIP} #{fakeARP} && "
         #
         # find the dns servers w/ wmic
         #
         @logger.lpStatus("   Checking DNS servers via WMIC...")
         dnsServers=[]
         raw=exec_wmi("nicconfig list full")
         raw.each_line do |l|
            if l =~ /DNSServerSearchOrder={/
               l[/.*{/]=""
               l[/}.*/]=""
               l.split(",").each do |d|
                  dnsServers.push(d.gsub("\"", "").strip)
               end
            end
         end
         #
         # add a null route for each
         #
         dnsServers.each do |d|
            cmdStr += "route add #{d} mask 255.255.255.255 #{nullIP} metric 1 && "
         end
         cmdStr[/ && $/]=""
         #
         # execute the commands
         #
         exec_cmd(cmdStr)
         @logger.lpGood("   Complete!")
      end

      if layer3
         @logger.lpStatus("   Isolating layer-3 w/ null route...")
         cmdStr=""
         #
         # static arp the null IP
         #
         cmdStr+="arp -s #{nullIP} #{fakeARP} && "
         #
         # add a route to maintain MSF connectivity
         #
         cmdStr+="route add #{metIP} mask 255.255.255.255 #{localGate} metric 1 && "
         #
         # route everything else to null
         #
         cmdStr+="route add 0.0.0.0 mask 0.0.0.0 #{nullIP} metric 1"
         #
         # exec the cmds
         #
         exec_cmd(cmdStr)
         @logger.lpGood("   Complete!")
      end

      if layer2
         if @session.sys.config.sysinfo['OS'] =~ /Windows 7/
            @logger.lpError("   Unable to effectively isolate layer-2 when OS >= Windows 7... exiting :(")
            return
         end
         @logger.lpStatus("   Isolating layer-2 with fake arp entries...")
         #
         # build the static arp command strings to isolate everything in the local subnet except the local ip, gateway, and meterpreter ip
         #
         cmdStr=""
         tmpIP=""
         rw.reset
         while tmpIP = rw.next_ip
            #
            # don't fake arp the local ip, gateway, or msf ip
            #
            next if tmpIP == localIP || tmpIP == localGate || tmpIP == metIP
            #
            # otherwise add the ip to the command string
            #
            cmdStr += "arp -s #{tmpIP} #{fakeARP} && "
            if cmdStr.length > maxCmdLen
               cmdStr[/&& $/]=""
               exec_cmd(cmdStr)
               cmdStr=""
            end
         end
         if cmdStr.length > 0
            cmdStr[/&& $/]=""
            exec_cmd(cmdStr)
         end
         @logger.lpGood("   Complete!")
      end
   end

   #
   ######################################################################################
   # monitor - redirect traffic from a remote host to a remote proxy via ssh tunnel and hosts file entries
   ######################################################################################
   #
   def monitor(teardown=false, tunnelIP="", tunnelUser="", tunnelPW="", proxyNfo="", hosts="")

      if @logger.is_system == false
         @logger.lpError("   ERROR: Unable to run effectively without SYSTEM... exiting :(")
         return
      end

      hostFile=@session.fs.file.expand_path("%SYSTEMROOT%") + "\\system32\\drivers\\etc\\hosts"
      hostsDelim="# # # # # # # # # # # #"
      pPID=nil

      if teardown
         @logger.lpStatus("   Tearing down monitor connection(s)...")
         #
         # read previously recorded info so we can kill pids and delete files
         #
         mp = @logger.readMonitorPIDs().compact
         if mp.count > 0
            mp.each do |m|
               tPID,tFile=m.split("|")
               @logger.lpStatus("   Killing #{tPID}...")
               begin
                  @session.sys.process.kill(tPID.to_i)
               rescue Rex::Post::Meterpreter::RequestError => re
                  @logger.lpError("   WARNING: PID #{tPID} doesn't appear to exist anymore...") if re.to_s =~ /The parameter is incorrect/
               end
               sleep(2)
               @logger.lpStatus("   Deleteing #{tFile}...")
               begin
                  @session.fs.file.rm(tFile)
               rescue Rex::Post::Meterpreter::RequestError => re
                  @logger.lpError("   WARNING: File #{tFile} doesn't appear to exist anymore...") if re.to_s =~ /system cannot find the file specified/
               end
            end
         end

         #
         # restore the hosts file; since we append to hosts, and start w/ our delimiter, this should be safe-ish...
         #
         @logger.lpStatus("   Restoring hosts file...")
         tmpHosts=""
         newHosts=""
         #
         # read the current hosts file
         #
         fd = @session.fs.file.new(hostFile, "r")
         until fd.eof?
            tmpHosts << fd.read
         end
         fd.close
         #
         # parse the hosts file and record the contents until we hit the delimiter
         #
         foundDelim=false
         tmpHosts.each_line do |l|
            if l =~ /#{hostsDelim}/
               foundDelim=true
               break
            end
            newHosts << l
         end
         #
         # if we found a delimiter, overwrite the hosts file w/ the pre-delimiter data, otherwise take no action
         #
         if foundDelim
            fd = @session.fs.file.new(hostFile, "w")
            fd.write(newHosts)
            fd.close
            @logger.lpGood("   hosts file restored")
         else
            @logger.lpStatus("   No hosts file changes found...")
         end
         #
         # now reset the record of what we killed/cleaned, and then return...
         #
         @logger.resetMonitorPIDs
         return
      end

      #
      # if any of these params are blank, we can't continue
      #
      if tunnelIP == "" || tunnelUser=="" || tunnelPW=="" || proxyNfo==""
         @logger.lpError("   ERROR: monitor(): A parameter other than 'hosts' was null, cannot continue...")
         return
      end
      @logger.lpStatus("   Building monitor connection...")
      #
      # upload putty
      #
      ptyName = @session.fs.file.expand_path("%TEMP%") + "\\"+ sprintf("%.5d",rand(100000)) + ".exe"
      @logger.lpStatus("   Uploading qutty as #{ptyName}")
      @session.fs.file.upload_file(ptyName, "#{@binpath}/qutty.exe")
      #
      # execute
      #
      @logger.lpStatus("   Executing tunnel w/ supplied params...")
      p = @session.sys.process.execute("#{ptyName}", "-N -L #{proxyNfo} -pw \"#{tunnelPW}\" #{tunnelUser}@#{tunnelIP}", {'Hidden' => 'true'})
      #
      # record the PID so we can tear down later...
      #
      daPID = p.pid
      p.close
      #
      # sleep a bit and then check for the pid to see if the execution worked
      #
      @logger.lpStatus("   Sleeping 10 seconds...")
      sleep(10)
      found = false
      @logger.lpStatus("   Checking for PID...")
      @session.sys.process.get_processes.each do |pl|
         found = true if pl['pid'] == daPID
      end
      if !found
         @logger.lpError("   ERROR: monitor(): Tunnel creation failed...")
         return
      else
         @logger.lpGood("   Monitor tunnel appears stable (no promises!!! bad password, bad remote ip, etc aren't easy to detect/control w/ putty)... recording PID...")
         @logger.addMonitorPID("#{daPID}|#{ptyName}")
      end
      #
      # update hosts file w/ redirect domains
      #
      if hosts != ""
         @logger.lpStatus("   Updating hosts file to redirect supplied domains to localhost: #{hosts}")
         hl = hosts.split(",")
         fd = @session.fs.file.new(hostFile, "a")
         fd.write("\r\n#{hostsDelim}\r\n")
         hl.each do |h|
            fd.write("127.0.0.1\t#{h}\r\n")
         end
         fd.close
      end
   end


   #
   ######################################################################################
   # autoruns - just a wrapper around the sysinternals tool
   ######################################################################################
   #
   def autoruns(verify=true, all=false)

      arunsUtil = @session.fs.file.expand_path("%TEMP%") + "\\" + sprintf("%.5d",rand(100000)) + ".exe"
      arunsCmd = " /accepteula -c -f"
      tmpout = ""

      arunsCmd += " -a" if all
      arunsCmd += " -v" if verify

      begin

         @logger.lpStatus("   Uploading autoruns to #{arunsUtil}")
         @session.fs.file.upload_file("#{arunsUtil}", "#{@binpath}/autorunsc.exe")

         @logger.lpStatus("   Executing autoruns...")
         r = @session.sys.process.execute("cmd.exe", "/c #{arunsUtil}#{arunsCmd}", {'Hidden' => true, 'Channelized' => true})
         while (d = r.channel.read)
            tmpout << d
         end
         r.channel.close
         r.close
         
         @logger.lpStatus("   Cleaning up...")
         @session.sys.process.execute("cmd.exe /c del #{arunsUtil}", nil, {'Hidden' => true})

      rescue ::Exception => e
         @logger.lpError("   ERROR: System.autoruns (0): #{e.class} - #{e}")
         raise Rex::Script::Completed
      end      
      #TODO> parse the tmpout data into a table for display
      @logger.gatherData("autoruns", tmpout)

   end

   #
   ######################################################################################
   # raw_mem_dump - a wrapper around win32-dd/win64-dd
   ######################################################################################
   #
   def raw_mem_dump()

      is64 = false
      is64 = true if @session.platform =~ /win64/
      
      mem_dump_bat = @session.fs.file.expand_path("%TEMP%") + "\\MemoryDD.bat"
      mem_dump_util = @session.fs.file.expand_path("%TEMP%") + "\\Memoryze.exe"
      mem_dump_dir = @session.fs.file.expand_path("%TEMP%") + "\\" + sprintf("%.5d",rand(100000)) + "\\"
      mem_dump_cmd = "-output #{mem_dump_dir}" 

      begin

         # upload file and bat
         if is64
           @logger.lpStatus("   Uploading #{mem_dump_util}")
           @session.fs.file.upload_file("#{mem_dump_util}", "#{@binpath}/memoryze/x64/Memoryze.exe")
           @logger.lpStatus("   Uploading #{mem_dump_bat}")
           @session.fs.file.upload_file("#{mem_dump_bat}", "#{@binpath}/memoryze/x64/MemoryDD.bat")
         else
           @logger.lpStatus("   Uploading #{mem_dump_util}")
           @session.fs.file.upload_file("#{mem_dump_util}", "#{@binpath}/memoryze/x86/Memoryze.exe")
           @logger.lpStatus("   Uploading #{mem_dump_bat}")
           @session.fs.file.upload_file("#{mem_dump_bat}", "#{@binpath}/memoryze/x86/MemoryDD.bat")
         end

         # execute
         @session.sys.process.execute("cmd.exe", "/c mkdir #{mem_dump_dir}", {'Hidden' => true})
         @logger.lpStatus("   Executing raw mem dump")
         r = @session.sys.process.execute("cmd.exe", "/c \"#{mem_dump_bat} #{mem_dump_cmd}\"", {'Hidden' => true, 'Channelized' => true})
         tmpout = ""
         while (d = r.channel.read)
            tmpout << d
            print "."
            STDOUT.flush
            sleep 1
         end
         r.channel.close
         r.close
         print "\!"
         
         STDOUT.flush
         

         # download raw dump files
         @session.fs.file.search(mem_dump_dir, "*.xml", true).each do |f|
            @logger.lpStatus("Downloading #{f['path']}\\#{f['name']}... ")
            @logger.gatherFile(f['name'], "#{f['path']}\\#{f['name']}")
         end
         @session.fs.file.search(mem_dump_dir, "*.img", true).each do |f|
            @logger.lpStatus("Downloading #{f['path']}\\#{f['name']}... ")
            @logger.gatherFile(f['name'], "#{f['path']}\\#{f['name']}")
         end

         # clean up (exe, sys, raw)
         @logger.lpStatus("   Cleaning up...")
         @session.sys.process.execute("cmd.exe /c del #{mem_dump_util}", nil, {'Hidden' => true})
         @session.sys.process.execute("cmd.exe /c del #{mem_dump_bat}", nil, {'Hidden' => true})
         @session.sys.process.execute("cmd.exe /c rmdir #{mem_dump_dir}", nil, {'Hidden' => true})
      
      rescue ::Exception => e
         @logger.lpError("   ERROR: System.raw_mem_dump (0): #{e.class} - #{e}")
         raise Rex::Script::Completed
      end
   end

end
