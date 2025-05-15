### インポート

# 数値・確率計算
import pandas as pd
import numpy as np

# 機械学習
from sklearn.datasets import load_wine
from sklearn.ensemble import IsolationForest
from sklearn.inspection import DecisionBoundaryDisplay
from sklearn.tree import plot_tree
# 描画
import matplotlib.pyplot as plt
from matplotlib.colors import ListedColormap
import seaborn as sns
plt.rcParams['font.family'] = 'Meiryo'

# ワーニング表示の抑制
import warnings
warnings.simplefilter('ignore')
df1=pd.read_csv("data.txt",delimiter=" ",header=None,names=["ack","syn","arp","icmp","traffic","port"])
print(df1)
clf = IsolationForest(n_estimators=500,contamination=0.002 ,max_features=6,
                      random_state=123)

# 学習
clf.fit(df1)

# 予測
pred = clf.predict(df1)  # -1: 異常値, 1: 正常値

# 決定境界からの距離を算出
dist = clf.decision_function(df1)
df1['anomaly'] = pred

# 異常値を表示（-1が異常、1が正常）
print(df1[df1['anomaly'] == -1])
print('異常データの数: ', (pred == -1).sum())
# ビンを0.01間隔で設定
bins = np.arange(-0.17, 0.26, 0.01)
# 描画領域の設定
fig, ax = plt.subplots(figsize=(7, 4))
# 閾値=0の垂直線の描画
ax.axvline(0, color='tab:red', ls='--', lw=0.7)
# 異常の領域（閾値未満）の塗りつぶし描画
ax.fill_between([-0.17, 0], 0, 100, color='lightpink', alpha=0.2)
# 異常スコアのヒストグラムの描画
sns.histplot(x=dist, bins=50, ec='white', ax=ax)
# 修飾
ax.set(xlabel='abnormaly level', ylabel='number of data', xlim=(-0.1, 0.31),
       ylim=(0, 100))
ax.grid(lw=0.5)
plt.show()
plt.figure(figsize=(100, 100))
