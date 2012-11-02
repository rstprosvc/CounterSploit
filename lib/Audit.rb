class Audit

   #
   ######################################################################################
   # initialize
   ######################################################################################
   #
   def initialize(session, auditPath, auditID, max_display_lines)
      #
      # set vars
      #
      @auditPath = auditPath
      @auditID = auditID
      @session = session
      @max_display_lines = max_display_lines
      @is_system = false
      @is_admin = false

      #
      # build curr audit info, mk dirs, and set audit log file
      #
      auditRunTime = "_" + ::Time.now.strftime("%Y%m%d")
      @currAuditDir = ::File.join(auditPath, Rex::FileUtils.clean_path(auditID + auditRunTime))
      if !::File.directory?(@currAuditDir)
         ::FileUtils.mkdir_p(@currAuditDir)
      end
      @auditLog = Rex::FileUtils.clean_path(@currAuditDir + "/" + auditID + auditRunTime + ".txt")
      @lastSysLogTime = Rex::FileUtils.clean_path(@auditPath + "/" + auditID + "_lastSysLog.time")
      @monitorPIDs = Rex::FileUtils.clean_path(@auditPath + "/" + auditID + "_monitor.PIDs")
   end

   attr_reader :currAuditDir, :auditPath, :auditID, :auditLog, :is_system, :is_admin, :max_display_lines
   attr_writer :is_system, :is_admin

   #
   ######################################################################################
   # setLastSysLogtime - write a timestamp for the current remote host so logs can be tailed
   ######################################################################################
   #
   def setLastSysLogTime(lsl=nil)
      if lsl
         File.open("#{@lastSysLogTime}", "w") { |daTime| daTime.write(lsl) }
      end
   end

   #
   ######################################################################################
   # getLastSysLogtime - read the last syslog read time for the current remote host, so logs can be tailed
   ######################################################################################
   #
   def getLastSysLogTime
      lsl=nil
      if ::File.exists?(@lastSysLogTime)
         lsl=File.read(@lastSysLogTime)
         lsl.strip! if lsl
      end
      lsl
   end

   #
   ######################################################################################
   # addMonitorPID - record the PID (and path) for a monitor exe for the current remote host (delimited w/ '?')
   ######################################################################################
   #
   def addMonitorPID(p=nil)
      if p
         File.open("#{@monitorPIDs}", "a") { |daPID| daPID.write("#{p}?") }
      end
   end

   #
   ######################################################################################
   # readMonitorPIDs - read the PIDs and paths for monitor exes for the current remote host
   ######################################################################################
   #
   def readMonitorPIDs
      p=[]
      if ::File.exists?(@monitorPIDs)
         p=File.read(@monitorPIDs).split("?")
      end
      p
   end

   #
   ######################################################################################
   # resetMonitorPIDs - zero out the monitor pid file
   ######################################################################################
   #
   def resetMonitorPIDs
      if ::File.exists?(@monitorPIDs)
         File.open("#{@monitorPIDs}", "w") { |daPID| daPID.write("") }
      end
   end

   #
   ######################################################################################
   # lpError - log and print an error message
   ######################################################################################
   #
   def lpError(msg) 
      begin
         @session.print_error("#{@auditID}: #{msg}")
         File.open("#{@auditLog}", "a") { |daLog| daLog.write(::Time.now.strftime("%Y%m%d-%H%M%S") + " [-] #{@auditID}: #{msg}\n") }
      rescue ::Exception => e
         @session.print_error("Audit.lpError: #{e.class} - #{e}")
      end
   end

   #
   ######################################################################################
   # lpGood - log and print a success message
   ######################################################################################
   #
   def lpGood(msg) 
      begin
         @session.print_good("#{@auditID}: #{msg}")
         File.open("#{@auditLog}", "a") { |daLog| daLog.write(::Time.now.strftime("%Y%m%d-%H%M%S") + " [+] #{@auditID}: #{msg}\n") }
      rescue ::Exception => e
         @session.print_error("Audit.lpGood: #{e.class} - #{e}")
      end
   end

   #
   ######################################################################################
   # lpStatus - log and print a status message
   ######################################################################################
   #
   def lpStatus(msg) 
      begin
         @session.print_status("#{@auditID}: #{msg}")
         File.open("#{@auditLog}", "a") { |daLog| daLog.write(::Time.now.strftime("%Y%m%d-%H%M%S") + " [*] #{@auditID}: #{msg}\n") }
      rescue ::Exception => e
         @session.print_error("Audit.lpStatus: #{e.class} - #{e}")
      end
   end

   #
   ######################################################################################
   # gatherFile - download a file from the remote host to the audit dir
   ######################################################################################
   #
   def gatherFile(evidenceName="", evidencePath="")
      if evidencePath == ""
         lpError("   ERROR: No path given... cannot proceed")
         return
      end
      if is_system == false
         lpError("   WARNING: Running without SYSTEM may limit the ability to gather files...")
      end
      #
      # we have to implement the hash mechanism b/c we don't have access to the FS object
      #
      begin
         file2hash = @session.fs.file.expand_path(evidencePath)
         hashVal = @session.fs.file.md5(file2hash).unpack('C*').map{ |b| "%02X" % b }.join('') # tytyty stackoverflow!
      rescue ::Exception => ex
         hashVal = ""
         lpError("   ERROR: Unable to hash #{evidenceName}")
      end
      #
      # download the file and save it w/ the time/date and hash info in the filename
      #
      begin
         localFileName = ::File.join(@currAuditDir, "#{::Time.now.strftime("%Y%m%d-%H%M%S")}_#{evidenceName}_#{hashVal}")
         lpStatus("   Downloading #{evidencePath} to #{localFileName} ...")
         @session.fs.file.download_file(localFileName, evidencePath)
         lpGood("   Complete!")
      rescue ::Exception => e
        @audit.lpError("ERROR: #{e.class} - #{e}")
      end
   end

   #
   ######################################################################################
   # gatherData - record a data blob to the audit dir for a remote host... works well w/ tbl.to_csv
   ######################################################################################
   #
   def gatherData(dataName, dataBlob)
      localFileName = ::File.join(@currAuditDir, "#{@auditID}_#{::Time.now.strftime("%Y%m%d-%H%M%S")}_#{dataName}")
      lpStatus("   Downloading #{dataName} to #{localFileName} ...")
      if not ::File.exists?(localFileName)
         ::FileUtils.touch(localFileName)
      end
      #output = ::File.open(localFileName, "w")
      output = ::File.open(localFileName, "wb")
      dataBlob.each_line do |d|
         output.puts(d)
      end
      output.close
      lpGood("   Complete!")
   end

   #
   ######################################################################################
   # gatherBin - record a blob of data to the local audit path (ie: memory images, etc)
   ######################################################################################
   #
   def gatherBin(dataName, dataBlob)
      localFileName = ::File.join(@currAuditDir, "#{@auditID}_#{::Time.now.strftime("%Y%m%d-%H%M%S")}_#{dataName}")
      lpStatus("   Downloading data to #{localFileName} ...")
      if not ::File.exists?(localFileName)
         ::FileUtils.touch(localFileName)
      end
      output = ::File.open(localFileName, "wb")
      output << dataBlob
      output.close
      lpGood("   Complete!")
   end
end
