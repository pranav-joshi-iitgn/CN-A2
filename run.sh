sudo echo "installing packages...";
sudo pip install -r requirements.txt > /dev/null 2>&1;
sudo echo "doing DNS configuration...";
sudo sh config.sh;
sudo echo "Cleaning mininet...";
sudo mn -c 1>/dev/null 2>/dev/null;
sudo echo "Starting script (output will be in topo.log)...";
sudo python3 topo.py 2>/dev/null;
sudo echo "reverting configuration...";
sudo sh unconfig.sh;
sudo echo "Doing Analysis..."
sudo python3 Analysis.py H1.csv 1> H1_analysis_result.txt 2>/dev/null;
sudo python3 Analysis.py H2.csv 1> H2_analysis_result.txt 2>/dev/null;
sudo python3 Analysis.py H3.csv 1> H3_analysis_result.txt 2>/dev/null;
sudo python3 Analysis.py H4.csv 1> H4_analysis_result.txt 2>/dev/null;
sudo python3 Analyse_stats.py 1> /dev/null 2> /dev/null;
sudo echo "Finished!"