| case | 封包 | 模式 | alert（sid×次數@第一個 pcap_cnt） | app_proto | 關鍵 stats（非 0） |
|---|---|---|---|---|---|
| h_full | 209 | ids | R1×2@144 R2×2@144 R3×3@144 R4×3@144 R5×1@157 R8×3@144 R9×1@175 | http | pkts=209 sess=1 http_flow=1 http_tx=20 |
| h_full | 209 | ips | R1×2@144 R2×2@144 R3×3@144 R4×3@144 R5×1@154 R8×3@144 R9×1@169 | http | pkts=209 acc=209 sess=1 http_flow=1 http_tx=20 |
| e1_i_req_start | 66 | ids | R1×1@34 R2×2@1 R3×2@11 R4×2@11 R5×1@14 R8×3@1 R9×1@32 | http | pkts=66 midstream=1 sess=1 http_flow=1 http_tx=6 |
| e1_i_req_start | 66 | ips | R1×1@34 R2×2@1 R3×1@11 R4×1@11 R5×1@11 R8×2@1 R9×1@26 | http | pkts=66 acc=66 midstream=1 sess=1 http_flow=1 http_tx=6 |
| e1_ii_srv_ack | 75 | ids | R1×2@10 R2×2@10 R3×2@10 R4×2@10 R5×1@23 R8×2@10 R9×1@41 | http | pkts=75 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_ii_srv_ack | 75 | ips | R1×2@10 R2×2@10 R3×3@10 R4×3@10 R5×1@20 R8×3@10 R9×1@35 | http | pkts=75 acc=75 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_iii_resp_start | 74 | ids | R1×2@9 R2×2@9 R3×3@9 R4×3@9 R5×1@22 R8×3@9 R9×1@40 | http | pkts=74 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_iii_resp_start | 74 | ips | R1×2@9 R2×2@9 R3×2@9 R4×2@9 R5×1@19 R8×2@9 R9×1@34 | http | pkts=74 acc=74 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_iv_resp_mid | 71 | ids | R1×2@6 R2×2@6 R4×2@6 R5×1@19 R9×1@- | http | pkts=71 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_iv_resp_mid | 71 | ips | R1×2@6 R2×2@6 R4×2@6 R5×1@16 R9×1@- | http | pkts=71 acc=71 midstream=1 sess=1 http_flow=2 http_tx=7 |
| e1_v_post_mid | 53 | ids | （無） | failed | pkts=53 midstream=1 sess=1 app_failed=1 |
| e1_v_post_mid | 53 | ips | （無） | failed | pkts=53 acc=53 midstream=1 sess=1 app_failed=1 |
| e2_one | 1 | ids | R2×1@1 R8×1@1 | http | pkts=1 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_one | 1 | ips | R2×1@1 R8×1@1 | http | pkts=1 acc=1 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_two | 2 | ids | R2×1@1 R8×1@1 | http | pkts=2 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_two | 2 | ips | R2×1@1 R8×1@1 | http | pkts=2 acc=2 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_three | 3 | ids | R2×1@1 R8×1@1 | http | pkts=3 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_three | 3 | ips | R2×1@1 R8×1@1 | http | pkts=3 acc=3 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_tx15_all | 10 | ids | R2×1@1 R8×1@1 | http | pkts=10 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e2_tx15_all | 10 | ips | R2×1@1 R8×1@1 | http | pkts=10 acc=10 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e3_c2s_hs | 87 | ids | R1×2@60 R2×2@60 R3×2@60 R4×2@60 R5×1@66 R8×2@60 | http | pkts=87 sess=1 ack_unseen=81 http_flow=1 http_tx=20 |
| e3_c2s_hs | 87 | ips | R1×2@60 R2×2@60 R3×3@60 R4×3@60 R5×1@64 R8×3@60 | http | pkts=87 acc=87 sess=1 ack_unseen=81 http_flow=1 http_tx=20 |
| e3_c2s_hs_dataonly | 26 | ids | R1×2@18 R2×2@18 R3×2@18 R4×2@18 R5×1@21 R8×2@18 | http | pkts=26 sess=1 ack_unseen=21 http_flow=1 http_tx=20 |
| e3_c2s_hs_dataonly | 26 | ips | R1×2@18 R2×2@18 R3×2@18 R4×2@18 R5×1@19 R8×2@18 | http | pkts=26 acc=26 sess=1 ack_unseen=21 http_flow=1 http_tx=20 |
| e3_c2s_mid | 48 | ids | R3×2@21 R4×2@21 R7×46@2 R8×2@21 | http | pkts=48 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e3_c2s_mid | 48 | ips | R3×2@21 R4×2@21 R7×46@2 R8×2@21 | http | pkts=48 acc=47 blk=1 drop_stream_err=1 midstream=1 sess=1 http_flow=1 http_tx=1 |
| e3_bulk_full | 6231 | ids | R1×1@4154 R2×1@4154 R3×1@4154 R4×1@4154 R8×1@4154 | http | pkts=6231 sess=1 http_flow=1 http_tx=3 |
| e3_bulk_full | 6231 | ips | R1×1@4154 R2×1@4154 R3×1@4154 R4×1@4154 R8×1@4154 | http | pkts=6231 acc=6231 sess=1 http_flow=1 http_tx=3 |
| e3_bulk_c2s | 2081 | ids | R1×1@1388 R2×1@1388 R3×1@1388 R4×1@1388 R8×1@1388 | http | pkts=2081 sess=1 ack_unseen=2075 http_flow=1 http_tx=3 |
| e3_bulk_c2s | 2081 | ips | R1×1@1388 R2×1@1388 R3×1@1388 R4×1@1388 R8×1@1388 | http | pkts=2081 acc=2081 sess=1 ack_unseen=2075 http_flow=1 http_tx=3 |
| e5_100k_gap10s | 30 | ids | R3×1@16 R4×1@16 R7×7@16 R8×1@16 R10×10@6 | - | pkts=30 sess=1 ack_unseen=1 gap=12 |
| e5_100k_gap10s | 30 | ips | R3×1@16 R4×1@16 R7×7@16 R8×1@16 R10×10@6 | - | pkts=30 acc=28 blk=2 drop_stream_err=2 sess=1 ack_unseen=1 gap=12 |
| e5_100k_gap60s | 30 | ids | R2×1@16 R3×2@20 R4×2@20 R8×3@16 R10×10@6 | -,http | pkts=30 midstream=1 sess=2 ack_unseen=1 gap=12 http_flow=1 http_tx=3 |
| e5_100k_gap60s | 30 | ips | R2×1@16 R3×2@20 R4×2@20 R8×3@16 R10×10@6 | -,http | pkts=30 acc=30 midstream=1 sess=2 ack_unseen=1 gap=12 http_flow=1 http_tx=3 |
| e5_2m_gap10s | 120 | ids | R3×1@61 R4×1@61 R7×43@4 R8×1@61 | - | pkts=120 sess=1 |
| e5_2m_gap10s | 120 | ips | R3×1@61 R4×1@61 R7×43@4 R8×1@61 | - | pkts=120 acc=118 blk=2 drop_stream_err=2 sess=1 |
| e5_2m_gap60s | 120 | ids | R2×1@61 R3×2@80 R4×2@80 R7×21@4 R8×3@61 | -,http | pkts=120 midstream=1 sess=2 http_flow=1 http_tx=3 |
| e5_2m_gap60s | 120 | ips | R2×1@61 R3×2@80 R4×2@80 R7×21@4 R8×3@61 | -,http | pkts=120 acc=120 midstream=1 sess=2 http_flow=1 http_tx=3 |
| e5_20m_gap10s | 930 | ids | R3×1@466 R4×1@466 R7×313@4 R8×1@466 | - | pkts=930 sess=1 |
| e5_20m_gap10s | 930 | ips | R3×1@466 R4×1@466 R7×313@4 R8×1@466 | - | pkts=930 acc=928 blk=2 drop_stream_err=2 sess=1 |
| e5_20m_gap60s | 930 | ids | R2×1@466 R3×2@620 R4×2@620 R7×156@4 R8×3@466 | -,http | pkts=930 midstream=1 sess=2 http_flow=1 http_tx=3 |
| e5_20m_gap60s | 930 | ips | R2×1@466 R3×2@620 R4×2@620 R7×156@4 R8×3@466 | -,http | pkts=930 acc=930 midstream=1 sess=2 http_flow=1 http_tx=3 |
| e5b_100k_gap10s | 66 | ids | R3×1@52 R4×1@52 R7×7@52 R8×1@52 | http | pkts=66 sess=1 http_flow=1 http_tx=12 |
| e5b_100k_gap10s | 66 | ips | R3×1@52 R4×1@52 R7×7@52 R8×1@52 | http | pkts=66 acc=64 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5b_100k_gap60s | 66 | ids | R2×1@52 R3×2@56 R4×2@56 R8×3@52 | http | pkts=66 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5b_100k_gap60s | 66 | ips | R2×1@52 R3×2@56 R4×2@56 R8×3@52 | http | pkts=66 acc=66 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5b_2m_gap10s | 291 | ids | R3×1@232 R4×1@232 R7×22@232 R8×1@232 | http | pkts=291 sess=1 http_flow=1 http_tx=12 |
| e5b_2m_gap10s | 291 | ips | R3×1@232 R4×1@232 R7×22@232 R8×1@232 | http | pkts=291 acc=289 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5c_2m_gap10s | 306 | ids | R3×1@247 R4×1@247 R7×28@232 R8×1@247 | http | pkts=306 sess=1 http_flow=1 http_tx=12 |
| e5c_2m_gap10s | 306 | ips | R3×1@247 R4×1@247 R7×28@232 R8×1@247 | http | pkts=306 acc=304 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5b_2m_gap60s | 291 | ids | R2×1@232 R3×2@251 R4×2@251 R8×3@232 | http | pkts=291 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5b_2m_gap60s | 291 | ips | R2×1@232 R3×2@251 R4×2@251 R8×3@232 | http | pkts=291 acc=291 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5c_2m_gap60s | 306 | ids | R1×1@247 R2×1@247 R3×3@247 R4×3@247 R8×3@247 | http | pkts=306 midstream=1 sess=2 http_flow=2 http_tx=16 |
| e5c_2m_gap60s | 306 | ips | R1×1@247 R2×1@247 R3×3@247 R4×3@247 R8×3@247 | http | pkts=306 acc=306 midstream=1 sess=2 http_flow=2 http_tx=16 |
| e5b_20m_gap10s | 2316 | ids | R3×1@1852 R4×1@1852 R7×157@1852 R8×1@1852 | http | pkts=2316 sess=1 http_flow=1 http_tx=12 |
| e5b_20m_gap10s | 2316 | ips | R3×1@1852 R4×1@1852 R7×157@1852 R8×1@1852 | http | pkts=2316 acc=2314 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5b_20m_gap60s | 2316 | ids | R2×1@1852 R3×2@2006 R4×2@2006 R8×3@1852 | http | pkts=2316 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5b_20m_gap60s | 2316 | ips | R2×1@1852 R3×2@2006 R4×2@2006 R8×3@1852 | http | pkts=2316 acc=2316 midstream=1 sess=2 http_flow=2 http_tx=15 |
| e5d_2m_ack1 | 1306 | ids | R1×1@1191 R2×1@1191 R3×3@1191 R4×3@1191 R8×3@1191 R10×1@1191 | http | pkts=1306 sess=1 ack_unseen=1016 gap=1 http_flow=1 http_tx=15 |
| e5d_2m_ack1 | 1306 | ips | R1×1@1191 R2×1@1191 R3×3@1191 R4×3@1191 R8×3@1191 R10×1@1191 | http | pkts=1306 acc=1306 sess=1 ack_unseen=1016 gap=1 http_flow=1 http_tx=15 |
| e5d_2m_ack10 | 392 | ids | R1×1@327 R2×1@327 R3×3@327 R4×3@327 R8×3@327 R10×1@327 | http | pkts=392 sess=1 ack_unseen=102 gap=1 http_flow=1 http_tx=15 |
| e5d_2m_ack10 | 392 | ips | R1×1@327 R2×1@327 R3×3@327 R4×3@327 R8×3@327 R10×1@327 | http | pkts=392 acc=392 sess=1 ack_unseen=102 gap=1 http_flow=1 http_tx=15 |
| e5d_2m_ack50 | 311 | ids | R3×1@251 R4×1@251 R7×39@233 R8×1@251 | http | pkts=311 sess=1 http_flow=1 http_tx=12 |
| e5d_2m_ack50 | 311 | ips | R3×1@251 R4×1@251 R7×39@233 R8×1@251 | http | pkts=311 acc=309 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5d_20m_ack1 | 9856 | ids | R1×1@8976 R2×1@8976 R3×3@8976 R4×3@8976 R8×3@8976 R10×1@8976 | http | pkts=9856 sess=1 ack_unseen=7541 gap=1 http_flow=1 http_tx=15 |
| e5d_20m_ack1 | 9856 | ips | R1×1@8976 R2×1@8976 R3×3@8976 R4×3@8976 R8×3@8976 R10×1@8976 | http | pkts=9856 acc=9856 sess=1 ack_unseen=7541 gap=1 http_flow=1 http_tx=15 |
| e5d_20m_ack10 | 3070 | ids | R1×1@2568 R2×1@2568 R3×3@2564 R4×3@2564 R8×3@2564 R10×1@2568 | http | pkts=3070 sess=1 ack_unseen=755 gap=1 http_flow=1 http_tx=15 |
| e5d_20m_ack10 | 3070 | ips | R1×1@2568 R2×1@2568 R3×3@2564 R4×3@2564 R8×3@2564 R10×1@2568 | http | pkts=3070 acc=3070 sess=1 ack_unseen=755 gap=1 http_flow=1 http_tx=15 |
| e5d_20m_ack50 | 2466 | ids | R3×1@1994 R4×1@1994 R7×307@1852 R8×1@1994 | http | pkts=2466 sess=1 http_flow=1 http_tx=12 |
| e5d_20m_ack50 | 2466 | ips | R3×1@1994 R4×1@1994 R7×307@1852 R8×1@1994 | http | pkts=2466 acc=2464 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| e5w_2m_noack | 291 | ids | R1×1@236 R2×1@236 R3×3@232 R4×3@232 R8×3@232 R10×1@236 | http | pkts=291 sess=1 ack_unseen=1 gap=1 http_flow=1 http_tx=15 |
| e5w_2m_noack | 291 | ips | R1×1@236 R2×1@236 R3×3@232 R4×3@232 R8×3@232 R10×1@236 | http | pkts=291 acc=291 sess=1 ack_unseen=1 gap=1 http_flow=1 http_tx=15 |
| e5w_20m_noack | 2316 | ids | R3×1@1852 R4×1@1852 R7×157@1852 R8×1@1852 | http | pkts=2316 sess=1 http_flow=1 http_tx=12 |
| e5w_20m_noack | 2316 | ips | R3×1@1852 R4×1@1852 R7×157@1852 R8×1@1852 | http | pkts=2316 acc=2314 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=12 |
| dpa_big_acks | 5568 | ids | R1×1@3479 R2×1@3479 R3×2@3479 R4×2@3479 R5×1@4871 R8×2@3479 R10×1@4871 | http | pkts=5568 sess=1 ack_unseen=5531 gap=1 http_flow=1 http_tx=8 |
| dpa_big_acks | 5568 | ips | R1×1@3479 R2×1@3479 R3×3@3479 R4×3@3479 R5×1@4174 R8×3@3479 R10×1@4871 | http | pkts=5568 acc=5568 sess=1 ack_unseen=5531 gap=1 http_flow=1 http_tx=8 |
| dpa_big_noacks | 31 | ids | R3×2@19 R4×2@19 R7×9@7 R8×2@19 | http | pkts=31 sess=1 http_flow=1 http_tx=1 |
| dpa_big_noacks | 31 | ips | R3×2@19 R4×2@19 R7×9@7 R8×2@19 | http | pkts=31 acc=29 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=1 |
| dpa_big_ack10 | 584 | ids | R1×1@365 R2×1@365 R3×3@365 R4×3@365 R5×1@510 R8×3@365 R10×1@510 | http | pkts=584 sess=1 ack_unseen=562 gap=1 http_flow=1 http_tx=8 |
| dpa_big_ack10 | 584 | ips | R1×1@365 R2×1@365 R3×2@365 R4×2@365 R5×1@437 R8×2@365 R10×1@510 | http | pkts=584 acc=584 sess=1 ack_unseen=562 gap=1 http_flow=1 http_tx=8 |
| e2b_insession_one | 37 | ids | R3×1@34 R4×1@34 R7×2@34 R8×1@34 | http | pkts=37 sess=1 http_flow=1 http_tx=3 |
| e2b_insession_one | 37 | ips | R3×1@34 R4×1@34 R7×2@34 R8×1@34 | http | pkts=37 acc=35 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=3 |
| e2b_insession_tx | 46 | ids | R3×1@34 R4×1@34 R7×5@34 R8×1@34 | http | pkts=46 sess=1 http_flow=1 http_tx=3 |
| e2b_insession_tx | 46 | ips | R3×1@34 R4×1@34 R7×5@34 R8×1@34 | http | pkts=46 acc=44 blk=2 drop_stream_err=2 sess=1 http_flow=1 http_tx=3 |
| dpa_500_acks | 127 | ids | R1×2@88 R2×2@88 R3×2@88 R4×2@88 R5×1@101 R8×2@88 R9×1@109 R10×20@12 | http | pkts=127 sess=1 ack_unseen=82 gap=20 http_flow=1 http_tx=20 |
| dpa_500_acks | 127 | ips | R1×2@88 R2×2@88 R3×2@88 R4×2@88 R5×1@94 R8×2@88 R9×1@103 R10×20@12 | http | pkts=127 acc=127 sess=1 ack_unseen=82 gap=20 http_flow=1 http_tx=20 |
| dpa_500_noacks | 46 | ids | R1×2@32 R2×2@32 R3×2@32 R4×2@32 R5×1@36 R8×2@32 R9×1@39 R10×20@7 | http | pkts=46 sess=1 ack_unseen=20 gap=20 http_flow=1 http_tx=20 |
| dpa_500_noacks | 46 | ips | R1×2@32 R2×2@32 R3×2@32 R4×2@32 R5×1@34 R8×2@32 R9×1@37 R10×20@7 | http | pkts=46 acc=46 sess=1 ack_unseen=20 gap=20 http_flow=1 http_tx=20 |
| dpa_2000_acks | 148 | ids | R1×2@102 R2×2@102 R3×3@102 R4×3@102 R5×1@118 R8×3@102 R9×1@127 R10×20@13 | http | pkts=148 sess=1 ack_unseen=63 gap=20 http_flow=1 http_tx=20 |
| dpa_2000_acks | 148 | ips | R1×2@102 R2×2@102 R3×3@102 R4×3@102 R5×1@109 R8×3@102 R9×1@120 R10×20@13 | http | pkts=148 acc=148 sess=1 ack_unseen=63 gap=20 http_flow=1 http_tx=20 |
| dpa_2000_noacks | 67 | ids | R1×2@46 R2×2@46 R3×3@46 R4×3@46 R5×1@53 R8×3@46 R9×1@57 R10×20@8 | http | pkts=67 sess=1 ack_unseen=22 gap=20 http_flow=1 http_tx=20 |
| dpa_2000_noacks | 67 | ips | R1×2@46 R2×2@46 R3×2@46 R4×2@46 R5×1@49 R8×2@46 R9×1@54 R10×20@8 | http | pkts=67 acc=67 sess=1 ack_unseen=22 gap=20 http_flow=1 http_tx=20 |
| m_full | 210 | ids | R3×41@126 R4×41@126 R6×1@126 R8×41@126 | mqtt | pkts=210 sess=1 mqtt_flow=1 mqtt_tx=101 |
| m_full | 210 | ips | R3×41@126 R4×41@126 R6×1@126 R8×41@126 | mqtt | pkts=210 acc=210 sess=1 mqtt_flow=1 mqtt_tx=101 |
| m_mid | 105 | ids | R3×41@21 R4×41@21 R6×1@21 R8×41@21 | mqtt | pkts=105 midstream=1 sess=1 mqtt_tx=51 |
| m_mid | 105 | ips | R3×41@21 R4×41@21 R6×1@21 R8×41@21 | mqtt | pkts=105 acc=105 midstream=1 sess=1 mqtt_tx=51 |
| m_two_gap10s | 22 | ids | R3×2@16 R4×2@16 R8×2@16 R10×1@10 | mqtt | pkts=22 sess=1 gap=1 mqtt_flow=1 mqtt_tx=1 |
| m_two_gap10s | 22 | ips | R3×2@16 R4×2@16 R8×2@16 R10×1@10 | mqtt | pkts=22 acc=22 sess=1 gap=1 mqtt_flow=1 mqtt_tx=1 |
| m_two_gap60s | 22 | ids | R3×2@16 R4×2@16 R6×1@16 R8×2@16 R10×1@10 | mqtt | pkts=22 midstream=1 sess=2 gap=1 mqtt_flow=1 mqtt_tx=4 |
| m_two_gap60s | 22 | ips | R3×2@16 R4×2@16 R6×1@16 R8×2@16 R10×1@10 | mqtt | pkts=22 acc=22 midstream=1 sess=2 gap=1 mqtt_flow=1 mqtt_tx=4 |
