sudo sh config.sh
sudo mn -c > /dev/null
sudo python3 topo.py
sudo sh unconfig.sh
sudo python3 Analysis.py H1.csv > H1_analysis_result.txt
sudo python3 Analysis.py H2.csv > H2_analysis_result.txt
sudo python3 Analysis.py H3.csv > H3_analysis_result.txt
sudo python3 Analysis.py H4.csv > H4_analysis_result.txt