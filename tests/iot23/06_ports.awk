# 06_ports.awk — 對 conn.log.labeled 統計每種標籤的（協定/目的埠）、conn_state、來源 IP。用法: awk -f 06_ports.awk <conn.log.labeled> > out.tsv，再用 06_ports_summary.py 彙整
BEGIN{FS="\t"}
/^#/ {next}
{
  lab=$NF; sub(/^.*   Malicious   /,"M:",lab); sub(/^\(empty\)   Benign   .*/,"Benign",lab); sub(/^\(empty\)   Benign.*/,"Benign",lab)
  key=lab "|" $7 "|" $6
  c[key]++
  st[lab "|" $12]++
  src[lab "|" $3]++
  n[lab]++
}
END{
  for(k in c) print "PORT\t" k "\t" c[k]
  for(k in st) print "STATE\t" k "\t" st[k]
  for(k in src) if(src[k]>=1000) print "SRC\t" k "\t" src[k]
  for(k in n) print "TOTAL\t" k "\t" n[k]
}
