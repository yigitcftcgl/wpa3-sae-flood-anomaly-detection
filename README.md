# wpa3-sae-flood-anomaly-detection
Machine learning-based anomaly detection system for identifying SAE Commit Flood attacks on WPA3 Wi-Fi networks. Includes PCAP analysis, attack simulation scripts, and detailed Jupyter notebooks for reproducible experiments.

![Modem WPA3 settings](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/modem_wpa3_settings.png)

Within the scope of this project, the target network was first switched from WPA2 to WPA3 Personal mode via the modem interface.
After this step, Kali Linux was installed on top of the Oracle VirtualBox virtualization software, which would be used to perform the attack. An external Wi-Fi adapter is required to carry out the SAE commit flood. Since Intel Wi-Fi adapters in laptops do not support monitor mode, a TP-Link Archer T2U Plus Wi-Fi adapter was purchased to observe WPA3 attacks and overcome this limitation.
![TP-Link Archer T2U Plus Wi-Fi adapter](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/adaptor.png)

During normal traffic, the number of packets slightly exceeds 80 packets per second. Within 145 seconds, a total of 4,686 packets were sent. At the same time, the command ping -c 100 google.com was executed to ping Google.com during normal traffic. The results were approximately around 20 ms.

![Wireshark I/O Graphs: normal_capture-01.cap](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/normal_capture.png)

When examining the attack code, it is evident that the traffic differs significantly from the normal_capture. As seen in Figure 16, striking results appear during the attack phase: the packet transmission rate has increased to 1,000 packets per second. Within 132 seconds, a total of 57,148 packets were sent. Additionally, during this process, the command ping -c 100 google.com was executed to ping Google.com. The results increased up to approximately 300 ms.One of the most important observations is that there were significant fluctuations in the ping results during the attack.

![Wireshark I/O Graphs: attack_capture-01.cap](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/attack_capture.png)

After carrying out the attack, the final stage of the project—anomaly detection—was performed. In this stage, the objective was to enable the automatic identification of attacks on network traffic captured during both attack and normal conditions, using anomaly detection algorithms.

Within this scope, .cap files obtained before and during the SAE Commit Flood attack were first analyzed in a Python program. Specifically, authentication packets (wlan.fc.subtype == 11) in the IEEE 802.11 protocol were filtered, focusing on the authentication traffic that is heavily targeted during the attack. In both traffic files, statistical features such as the time difference between packets and the instantaneous packet rate were extracted. Using these feature vectors, anomaly detection was performed with the Local Outlier Factor (LOF) algorithm. The LOF algorithm, trained on normal traffic, successfully detected the abnormal packet rate and low delta-t values observed during the attack as anomalies. Thresholds for anomalous behavior were determined as the packet interval dropping below 0.002 seconds and the instantaneous packet rate exceeding 600 packets per second. In other words, a concrete criterion for distinguishing anomalies was defined, and LOF statistically determined all anomalies in the dataset.

As a result of the analysis, metrics such as confusion matrix, F1 score, accuracy, sensitivity, and specificity were calculated based on the LOF predictions and the labels generated for attack traffic, achieving high accuracy rates. An optimal contamination rate was set so that 20% of normal traffic was accepted as anomaly, which statistically revealed the clear distinction between attack and normal traffic.

Visualization results showed that, during the attack, packets were transmitted at very short intervals and extremely high speeds, and that the diversity of source MAC addresses increased significantly compared to normal traffic. The significant fluctuations and delays observed in ping times under attack further confirmed the impact of the attack on network performance.

In conclusion, this study demonstrated the practical implementation of an SAE Commit Flood attack on the WPA3 protocol, its effects on network traffic, and how such attacks can be detected with high accuracy using a machine learning-based anomaly detection mechanism. This underlines the necessity of additional defense layers and automatic detection systems against protocol-level attacks in modern wireless networks.

![Normal Traffic: Anomaly Results and Statistics](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/1.png)

![Attack Traffic: Anomaly Results and Statistics](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/2.png)

![Confusion Matrix of Local Outlier Factor Predictions](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/blob/main/Images/3.png)
