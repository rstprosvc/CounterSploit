class FS

   #
   ######################################################################################
   # initialize
   ######################################################################################
   #
   def initialize(session, logger, binpath)
      @session = session
      @logger = logger
      @binpath = binpath
   end

 protected

   #
   ######################################################################################
   # enumDrives - enumerate drives available on the remote system (tx mubix!)
   ######################################################################################
   #
   def enumDrives()
      bitmask = @session.railgun.kernel32.GetLogicalDrives()["return"]
      drives = []
      letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      (0..25).each do |i|
         test = letters[i,1]
         rem = bitmask % (2**(i+1))
         if rem > 0
            drives << "#{test}:\\"
            bitmask = bitmask - rem
         end
      end
      return drives
   end


 public

   #
   ######################################################################################
   # quickHash - pass in a path to a single file and return an md5
   ######################################################################################
   #
   def quickHash(file2hash)
      begin
         file2hash = @session.fs.file.expand_path(file2hash)
         retVal = @session.fs.file.md5(file2hash).unpack('C*').map{ |b| "%02X" % b }.join('') # tytyty stackoverflow!
      rescue Rex::Post::Meterpreter::RequestError => re
         if re.to_s.scan(/core_channel_open: Operation failed: Access is denied/)
            retVal = "Access denied: #{file2hash}"
         else
            retVal = "Error: #{re.class} - #{re}"
         end
      rescue ::Exception => ex
         retVal = "Error: #{ex.class} - #{ex}"
      ensure
         return retVal
      end
   end
    
   #
   ######################################################################################
   # hash - accepts array of potential targets; dirs are enumerated but not recursed
   ######################################################################################
   #  
   def hash(hashTargets=[], wlArr=[])
      if @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM may limit the ability to hash files...")
      end
      begin
         tmpHash=""
         if hashTargets.length > 0
            tbl = Msf::Ui::Console::Table.new(
                     Msf::Ui::Console::Table::Style::Default,
                     'Header' => "File Hash Info",
                     'Prefix' => "\n",
                     'Postfix' => "\n",
                     'Columns' => [ 'File Path', 'MD5' ] )

            @logger.lpStatus("   Attempting to hash #{hashTargets.length} targets...")
            hashTargets.each do |ht|
               begin
                  #
                  # remove whitespace and trailing slashes and expand envars
                  #
                  ht.strip!
                  if ht =~ /\\$/
                     ht[/\\+$/]=""
                  end
                  ht = @session.fs.file.expand_path(ht)
                  #
                  # if the target is some type of valid point on the fs
                  #
                  if @session.fs.file.stat(ht)
                     begin
                        # 
                        # if the target is a dir, enum but don't recurse 
                        # 
                        if @session.fs.file.stat(ht).directory?
                           @logger.lpStatus("   Hash target (#{ht}) is a directory with #{@session.fs.dir.entries(ht).count-2} potential targets")
                           @session.fs.dir.entries(ht).each do |f|
                              print "."
                              STDOUT.flush
                              aFile="#{ht}\\#{f}"
                              #
                              # ignore ./ and ../
                              #
                              if f =~ /^\.$/ || f =~ /^\.\.$/
                                 next
                              elsif @session.fs.file.stat(aFile).directory?
                                 @logger.lpError("   WARNING: #{aFile} is a directory... ignoring...")
                                 next
                              end
                              tmpHash=quickHash(aFile)
                              if wlArr.length > 0
                                 next if wlArr.include?(tmpHash.upcase)
                              end
                              tbl << [ aFile, tmpHash ]
                           end
                        else
                           print "."
                           STDOUT.flush
                           tmpHash=quickHash(ht)
                           if wlArr.length > 0
                              next if wlArr.include?(tmpHash.upcase)
                           end
                           tbl << [ ht, tmpHash ]
                        end
                     rescue ::Exception => e
                        @logger.lpError("   ERROR: FS.hash (2): #{e.class} - #{e}")
                     end
                  end
               rescue Rex::Post::Meterpreter::RequestError => r
                  if r.to_s.scan(/stdapi_fs_stat: Operation failed: The system cannot find the file specified/)
                     @logger.lpStatus("   WARNING: Hash target (#{ht}) cannot be found")
                  else
                     @logger.lpError("   ERROR: FS.hash (1): Hash target (#{ht}) generated an exception: #{r.class} - #{r}")
                  end
               end
            end
            print "!\n"
            STDOUT.flush
            @logger.gatherData("file_hash", tbl.to_csv)
            if (tbl.rows.length > @logger.max_display_lines)
               @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
            else
               @logger.lpGood(tbl.to_s)
            end
         else
            @logger.lpError("   WARNING: No hash targets given; n0p...")
         end
      rescue ::Exception => e
         @logger.lpError("   ERROR: FS.hash (0): #{e.class} - #{e}")
         return
      end
   end


   #
   ######################################################################################
   # file-system listing
   ######################################################################################
   #
   def list(path=nil, searchBlobs=["*"], recurse=true, stat=false, hash=false, raw=false, bound=nil, upper=nil, lower=nil, wlArr=[])

      if @logger.is_system == false
         @logger.lpError("   WARNING: Running without SYSTEM may limit the ability to enumerate, stat, and/or hash files...")
      end

      if path == nil || path == ""
         @logger.lpStatus("   No path given, enumerating drives:")
         enumDrives().each do |drive|
            @logger.lpGood("   #{drive}")
         end
      else
         path.strip!
         #
         # a full fs listing via path=all doesn't give you the option to stat or hash... 
         #
         if path =~ /^all$/i
            tbl = Msf::Ui::Console::Table.new(
                     Msf::Ui::Console::Table::Style::Default,
                     'Header' => "FS Listing for: #{path}",
                     'Prefix' => "\n",
                     'Postfix' => "\n",
                     'Columns' => [ 'Path', 'Name', 'Size' ] )
            
            enumDrives.each() do |drive|
               searchBlobs.each do |s|
                  @logger.lpStatus("   Searching #{drive} for #{s}")
                  @logger.lpStatus("   Recurse := #{recurse}")
                  begin
                     @session.fs.file.search(drive, s, recurse).each do |f|
                        print "."
                        STDOUT.flush
                        tbl << f.values
                     end
                     print "!\n"
                     STDOUT.flush
                  rescue Rex::Post::Meterpreter::RequestError => e
                     @logger.lpError("WARNING: FS.list(): Unable to search #{drive} for #{s}: #{e.class} - #{e}")
                     return
                  end
               end
            end
            @logger.gatherData("fs_list_#{path}", tbl.to_csv)
         else  
            tbl = Msf::Ui::Console::Table.new(
                     Msf::Ui::Console::Table::Style::Default,
                     'Header' => "FS Listing for: #{path}",
                     'Prefix' => "\n",
                     'Postfix' => "\n",
                     'Columns' => [ 'Name', 'Path', 'Size', 'Dev', 'Ino', 'Mode', 'Nlink', 'UID', 'GID', 
                                    'Pad1', 'Rdev', 'Size', 'ATime', 'MTime', 'CTime', 'MD5' ] )
            path = @session.fs.file.expand_path(path)
            #
            # set the timezone to Zulu; timezones, DST, and remote vs local machines adds too much complication
            #
            tz="-00:00"
            #
            # do some simple validation if we need it
            #
            if bound
               if !upper || !lower
                  @logger.lpError("   Error: FS.list(): upper and/or lower bound values missing")
                  return
               elsif upper.length != 14 || lower.length != 14
                  @logger.lpError("   Error: FS.list(): Incorrect upper/lower format (YYYYMMDDHHmmSS); upper:=#{upper}; lower:=#{lower}")
                  return
               end
            end
            #
            # each search blob gets an iteration
            #
            searchBlobs.each do |s|
               @logger.lpStatus("   Searching #{path} for #{s}")
               @logger.lpStatus("   Recurse := #{recurse}")
               begin
                  #
                  # search the fs for our current search blob
                  #
                  @session.fs.file.search(path, s, recurse).each do |f|
                     print "."
                     STDOUT.flush
                     tr=[]
                     #
                     # record the basic info we can gather without performing a stat
                     #
                     tr.push(f['name'])
                     tr.push(f['path'])
                     tr.push(f['size'])
                     #
                     # if we're performing a stat
                     #
                     if stat
                        #
                        # stat it and grab the return vals
                        #
                        stats = @session.fs.file.stat("#{f['path']}\\#{f['name']}")
                        vals = stats.stathash.values
                        #
                        # if the search results will be bounded by time...
                        #
                        if bound
                           #
                           # store the proper time value we're checking versus the time boundaries
                           #
                           case bound
                           when /atime/i
                              theTime=vals[9].to_i
                           when /mtime/i
                              theTime=vals[10].to_i
                           when /ctime/i
                              theTime=vals[11].to_i
                           else
                              @logger.lpError("   ERROR: FS.list(): Unknown bound value: #{bound}")
                              return
                           end
                           #
                           # parse upper and lower time boundaries to epoch
                           #
                           lowerE = Time.new(lower[0..3].to_i, lower[4..5].to_i, lower[6..7].to_i, lower[8..9].to_i, lower[10..11].to_i, lower[12..13].to_i, "#{tz}").to_i
                           upperE = Time.new(upper[0..3].to_i, upper[4..5].to_i, upper[6..7].to_i, upper[8..9].to_i, upper[10..11].to_i, upper[12..13].to_i, "#{tz}").to_i
                           #
                           # if this file is outside the boundary we're searching, just move onto the next file
                           #
                           if theTime > upperE || theTime < lowerE
                              next
                           end
                        end
                        #
                        # if the user doesn't want epoch times, just overwrite the epoch vals we already stored w/ human-readable time
                        #
                        if not raw
                           vals[9] = Time.at(vals[9]).localtime(tz)
                           vals[10] = Time.at(vals[10]).localtime(tz)
                           vals[11] = Time.at(vals[11]).localtime(tz)
                        end
                        #
                        # push the stat data into the table row array
                        #
                        vals.each do |v|
                           tr.push(v)
                        end
                     #
                     # if the user didn't want to stat, just null out those values
                     #
                     else
                        (0..11).each do |null|
                           tr.push("")
                        end
                     end
                     #
                     # calc the file hash if needed
                     #
                     hashVal=""
                     if hash
                        hashVal=quickHash("#{f['path']}\\#{f['name']}")
                     end
                     tr.push(hashVal)
                     if hash and wlArr.length > 0
                        next if wlArr.include?(hashVal.upcase)
                     end
                     #
                     # record the table row vals into the output table, and move onto the next file
                     #
                     tbl << tr
                  end
               rescue Rex::Post::Meterpreter::RequestError => e
                  @logger.lpError("WARNING: FS.list(): Unable to search #{path} for #{s}: #{e.class} - #{e}")
               end
               print "!\n"
               STDOUT.flush
            end
            #
            # report the findings to the user
            #
            if tbl.rows.length == 0
               @logger.lpStatus("   No data returned for the parameters given...")
            else
               @logger.gatherData("fs_list_#{path}", tbl.to_csv)
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
   ######################################################################################
   # ADS file listing
   ######################################################################################
   #
   def ads_list(path=nil)

      if not path || path == ""
         @logger.lpStatus("   No path given, searching %SYSTEMDRIVE%...")
         path="%SYSTEMDRIVE%\\"
      end
      path = @session.fs.file.expand_path(path)

      #
      # ads_dump has a quirk, where it wants a trailing \ for c:\, but doesn't want one for c:\directory\ (no data returned)
      #
      path[/\\$/]="" if path =~ /\\$/ && path !~ /:\\$/

      tbl = Msf::Ui::Console::Table.new(
               Msf::Ui::Console::Table::Style::Default,
               'Header' => "ADS Listing for: #{path}",
               'Prefix' => "\n",
               'Postfix' => "\n",
               'Columns' => [ 'Info' ] )

      adsUtil = @session.fs.file.expand_path("%TEMP%") + "\\" + sprintf("%.5d",rand(100000)) + ".exe"
      tmpout = ""

      begin

         @logger.lpStatus("   Uploading ads_dump.exe to #{adsUtil}")
         @session.fs.file.upload_file("#{adsUtil}", "#{@binpath}/ads_dump.exe")

         @logger.lpStatus("   Searching path: #{path}")
         r = @session.sys.process.execute("cmd.exe", "/c #{adsUtil} #{path}", {'Hidden' => true, 'Channelized' => true})
        
         while (d = r.channel.read)
            tmpout << d
         end
         r.channel.close
         r.close
         
         @logger.lpStatus("   Cleaning up...")
         @session.sys.process.execute("cmd.exe /c del #{adsUtil}", nil, {'Hidden' => true})

         @logger.lpStatus("   Reading output...")
         if tmpout =~ /No NTFS ADS found/
            @logger.lpError("   No ADS info found in path: #{path}")
            return
         end
         tmpout.each_line do |l|
            tbl << [ l.strip ] if l =~ /^Found NTFS ADS/
         end
      rescue ::Exception => e
         @logger.lpError("   ERROR: FS.ads_list (0): #{e.class} - #{e}")
         raise Rex::Script::Completed
      end      
      @logger.gatherData("ads_list_#{path}", tbl.to_csv)
      if (tbl.rows.length > @logger.max_display_lines)
         @logger.lpStatus("   Skipping output display because length is greater than the configured max display... check audit/ for your data!")
      else
         @logger.lpGood(tbl.to_s) 
      end
   end
end
