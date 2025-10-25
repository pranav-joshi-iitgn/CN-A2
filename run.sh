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
sudo python3 Analysis.py H1.csv > H1_analysis_result.txt;
sudo python3 Analysis.py H2.csv > H2_analysis_result.txt;
sudo python3 Analysis.py H3.csv > H3_analysis_result.txt;
sudo python3 Analysis.py H4.csv > H4_analysis_result.txt;
sudo echo "Finished!"