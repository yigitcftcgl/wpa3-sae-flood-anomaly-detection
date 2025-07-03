import pyshark
import numpy as np
import matplotlib.pyplot as plt
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score, precision_score, recall_score
import warnings
import seaborn as sns
warnings.filterwarnings('ignore')

def extract_wlan_packets(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="wlan.fc.subtype == 11")
    packets_info = {'timestamps': [], 'src_macs': []}
    for pkt in cap:
        try:
            packets_info['timestamps'].append(float(pkt.sniff_timestamp))
            if hasattr(pkt.wlan, 'sa'):
                packets_info['src_macs'].append(str(pkt.wlan.sa))
            else:
                packets_info['src_macs'].append('unknown')
        except:
            continue
    cap.close()
    for key in packets_info:
        packets_info[key] = np.array(packets_info[key])
    return packets_info

def compute_features(packets_info, window_size=10):
    timestamps = packets_info['timestamps']
    if len(timestamps) < 2:
        return np.array([])
    delta_t = np.diff(timestamps)
    min_delta = 1e-6
    delta_t = np.maximum(delta_t, min_delta)
    rate = 1 / delta_t
    features = []
    for i in range(len(delta_t)):
        if i >= window_size:
            window_rates = rate[i-window_size:i]
            window_features = [
                np.mean(window_rates),
                np.std(window_rates),
                np.max(window_rates),
                np.min(window_rates)
            ]
        else:
            window_features = [rate[i], 0, rate[i], rate[i]]
        features.append([delta_t[i], rate[i]] + window_features)
    return np.array(features)

def create_labels_for_training(features, traffic_type='normal'):
    if traffic_type == 'normal':
        return np.zeros(len(features))
    else:
        rate = features[:, 1]
        delta_t = features[:, 0]
        high_rate = rate > 600
        low_delta = delta_t < 0.002
        labels = (high_rate | low_delta).astype(int)
        return labels

def calculate_metrics(y_true, y_pred):
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, zero_division=0),
        'recall': recall_score(y_true, y_pred, zero_division=0),
        'f1_score': f1_score(y_true, y_pred, zero_division=0)
    }

def train_lof(normal_features, contamination=0.2, n_neighbors=20):
    scaler = StandardScaler()
    normal_scaled = scaler.fit_transform(normal_features)
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=contamination, novelty=True)
    lof.fit(normal_scaled)
    return lof, scaler

def detect_anomalies_lof(model, scaler, features):
    features_scaled = scaler.transform(features)
    preds = model.predict(features_scaled)
    lof_anomalies = (preds == -1).astype(int)
    scores = model.decision_function(features_scaled)
    return lof_anomalies, scores

def plot_results(features, lof_anomalies, scores, packets_info, traffic_type):
    fig = plt.figure(figsize=(16, 6))
    
    ax1 = plt.subplot(1, 4, 1)
    time_series = np.cumsum(features[:, 0])
    ax1.scatter(time_series, features[:, 1], c=lof_anomalies, cmap='coolwarm', s=10, alpha=0.7)
    ax1.set_xlabel('Zaman (saniye)')
    ax1.set_ylabel('Paket Oranı (paket/saniye)')
    ax1.set_title(f'Paket Oranı Zaman Serisi - {traffic_type.upper()}')
    ax1.set_yscale('log')
    ax1.grid(True, alpha=0.3)

    ax2 = plt.subplot(1, 4, 2)
    ax2.plot(scores, 'b-', linewidth=0.5, alpha=0.7)
    ax2.axhline(y=0, color='r', linestyle='--', label='Anomali Sınırı')
    ax2.set_title('LOF Anomali Skorları')
    ax2.set_ylabel('Skor')
    ax2.set_xlabel('Paket İndeksi')
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    ax3 = plt.subplot(1, 4, 3)
    ax3.axis('off')
    lof_anomaly_count = np.sum(lof_anomalies)
    lof_ratio = lof_anomaly_count / len(features) * 100
    unique_macs = len(set(packets_info['src_macs']))
    total_packets = len(packets_info['src_macs'])

    summary_text = f"""
TRAFİK ANALİZİ - {traffic_type.upper()}

Paket İstatistikleri:
Authentication Filtreli Toplam Paket: {len(features):,}

Anomali Tespiti:
LOF: {lof_anomaly_count:,} ({lof_ratio:.1f}%)

MAC Adresi Analizi:
Benzersiz MAC: {unique_macs}
MAC Çeşitliliği: {unique_macs/total_packets:.1%}
"""
    ax3.text(0.1, 0.5, summary_text, fontsize=10, verticalalignment='center',
             fontfamily='monospace',
             bbox=dict(boxstyle='round,pad=0.5', facecolor='lightgray', alpha=0.8))
    plt.tight_layout()
    plt.show()

def plot_confusion_matrix(y_true, y_pred, title):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(7, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Anomali'],
                yticklabels=['Normal', 'Anomali'])
    
    plt.title(title)
    plt.ylabel('Gerçek Etiket')
    plt.xlabel('Tahmin')
    plt.tight_layout()
    plt.show()

def analyze_sae_flood_lof(normal_pcap, attack_pcap):
    print("SAE FLOOD TESPİT SİSTEMİ")
    print("\nPCAP dosyaları yükleniyor")
    normal_packets = extract_wlan_packets(normal_pcap)
    attack_packets = extract_wlan_packets(attack_pcap)
    print("\nÖzellikler çıkarılıyor")
    normal_features = compute_features(normal_packets)
    attack_features = compute_features(attack_packets)
    print("\nLOF modeli eğitiliyor")
    model, scaler = train_lof(normal_features)
    print("\nNormal trafik analiz ediliyor")
    normal_lof_anomalies, normal_lof_scores = detect_anomalies_lof(model, scaler, normal_features)
    print(f"Normal Trafik - LOF ile anomali oranı: {np.sum(normal_lof_anomalies)}/{len(normal_lof_anomalies)} ({np.sum(normal_lof_anomalies)/len(normal_lof_anomalies)*100:.2f}%)")
    print("\nAttack trafiği analiz ediliyor")
    attack_lof_anomalies, attack_lof_scores = detect_anomalies_lof(model, scaler, attack_features)
    y_true_attack = create_labels_for_training(attack_features, 'attack')
    metrics_lof = calculate_metrics(y_true_attack, attack_lof_anomalies)
    print("\nLOF Performansı (Attack Trafiği):")
    
    for key, value in metrics_lof.items():
        print(f"{key.capitalize()}: {value:.3f}")
    
    print(f"\nTrafik Karşılaştırması:\nNormal trafik: {len(normal_features):,} paket(Authentication filtreli paket sayısı)\nAttack trafiği: {len(attack_features):,} paket(Authentication filtreli paket sayısı)")
    plot_results(normal_features, normal_lof_anomalies, normal_lof_scores, normal_packets, 'normal')
    plot_results(attack_features, attack_lof_anomalies, attack_lof_scores, attack_packets, 'attack')
    plot_confusion_matrix(y_true_attack, attack_lof_anomalies, 'LOF - Attack Trafiği')
    return model, scaler

if __name__ == "__main__":
    normal_pcap = "normal_capture2-01.cap"
    attack_pcap = "attack_capture-01.cap"
    model, scaler = analyze_sae_flood_lof(normal_pcap, attack_pcap)
