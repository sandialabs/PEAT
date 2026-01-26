
export {
    const default_logdir = "" &redef;
}

event file_new(f: fa_file)
     {
     if ( f$source != "FTP_DATA" )
         return;

     for ( cid in f$conns )
         {
         if ( f$conns[cid]?$ftp )
             {
             print fmt("Command: %s", f$conns[cid]$ftp$command);
             }
         }

     local fname = fmt("%s_%s.bin", to_lower(f$source), f$id);
     Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
     }