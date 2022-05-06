# Steps to Run
1. First Clone the repository and make sure P4 is set up on your system:
```git clone https://github.com/sankalpmittal1911-BitSian/IITH-RA-Project-Extracting-Flow-Features-Efficiently```

2. Download the CICIDS dataset and PCAP files from (you can extend this to live traffic as well): https://www.unb.ca/cic/datasets/ids-2017.html


3. Train any one of ML model using ```python RF.py```, ```python SVM.py``` or ```python DT.py```

4. Go to the terminal and enter the following commands:

  (i). ```sudo p4run```

  (ii). ```xterm s1```

  (iii). ```sudo ifconfig s1-eth1 mtu 65500 up```

  (iv). ```sudo tcpreplay --intf1-eth1 some_file.pcap``` 

5. Open one more terminal window and type (parallely):
```python feature_handler.py```

6. Wait for the whole process to run and note the flows being classified dynamically.

7. Once classification is done, we evaluate the models by getting accuracy metrics using:
```python evaluate.py```
