import matplotlib.pyplot as plt

def plot_intervals(intervals, src, dst):
    plt.figure(figsize=(8, 4))
    plt.plot(intervals, marker='o')
    plt.title(f"Beacon Pattern: {src} ➝ {dst}")
    plt.xlabel("Connection Index")
    plt.ylabel("Interval (seconds)")
    plt.grid(True)
    plt.tight_layout()
    plt.show()
