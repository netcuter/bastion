for pid in /proc/[0-9]* ; do
  echo $pid;
  read linia < $pid/status; 
  echo $linia;
  while IFS= read -r -d '' linia; do 
   bufor+="${linia%%$*}"; 
   echo -n -e "${bufor} "; 
   bufor="";
  done < $pid/cmdline;
  echo $linia;  
  echo -e "\n";
done
