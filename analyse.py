#!/usr/bin/env python3

import os
import sys
from flask.cli import F
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import re
import matplotlib.ticker as ticker

def parse_filename(filename):
    """Extracts workers and threads from the filename using regex."""
    match = re.search(r'workers_(\d+)_threads_(\d+)', filename)
    if match:
        workers = int(match.group(1))
        threads = int(match.group(2))
        return workers, threads
    return None, None

def load_and_process_files(folder_path):
    """Loads all *detailed.csv files, extracts worker/thread counts, and concatenates the data, filtering out aggregated results."""
    all_data = []
    
    for filename in os.listdir(folder_path):
        if filename.endswith("detailed.csv"):  # Ensure only locust stats history files are processed
            workers, threads = parse_filename(filename)
            if workers is not None and threads is not None:
                file_path = os.path.join(folder_path, filename)
                df = pd.read_csv(file_path)  # Load CSV file into a DataFrame
                df = df[df["Name"] != "Aggregated"]  # Filter out aggregated results
                df["Workers"] = workers  # Append workers count as a new column
                df["Threads"] = threads  # Append threads count as a new column
                all_data.append(df)
    
    if not all_data:
        raise ValueError("No valid locust stats history files found in the folder.")
    
    return pd.concat(all_data, ignore_index=True)  # Combine all data into a single DataFrame

def generate_heatmaps(data, folder_path):
    """Generates heatmaps showing failure rate by endpoint."""

    # Remove all status code 0 entries (failed requests)
    data = data[data["Status Code"] != 0]

    # Create a copy to avoid SettingWithCopyWarning
    data = data.copy()
    
    # Identify failures based on status code 5xx in the Exception column
    data.loc[:, "Failure"] = data["Exception"].fillna("").str.startswith("5")

    # Group by endpoint, workers, and threads
    grouped = data.groupby(["Name", "Workers", "Threads"]).agg(
        Total_Requests=("Name", "count"),
        Total_Failures=("Failure", "sum")
    ).reset_index()

    # Calculate failure rate as percentage
    grouped.loc[:, "Failure Rate"] = (grouped["Total_Failures"] / grouped["Total_Requests"]) * 100
    
    # Get all unique API endpoints from the Name column
    unique_endpoints = grouped["Name"].unique()
    
    # Generate a heatmap for each API endpoint
    for endpoint in unique_endpoints:
        df_filtered = grouped[grouped["Name"] == endpoint]  # Filter data for the current endpoint

        pivot_table = df_filtered.pivot_table(values="Failure Rate", index="Threads", columns="Workers", aggfunc="mean")
        
        plt.figure(figsize=(10, 8))  # Set figure size
        sns.heatmap(pivot_table, annot=True, cmap="coolwarm", fmt=".2f", vmin=0, vmax=100)  # Create heatmap
        plt.title(f"Failure Rate (%) - {endpoint}")  # Set title
        plt.xlabel("Workers")  # Label x-axis
        plt.ylabel("Threads")  # Label y-axis
        
        output_path = os.path.join(folder_path, f"failure_rate_{endpoint.replace('/', '_')}.png")
        plt.savefig(output_path)
        plt.close()

def generate_response_time_analysis(data, folder_path):
    """
    Generates boxplots and summary statistics for response time across different workers/threads
    configurations for each API endpoint. Filters out any result with status code different from 2xx.
    """
    # Filter only successful responses (2xx status codes)
    data = data[data["Status Code"].astype(str).str.startswith("2")]
    
    # Create a directory to save plots if it doesn't exist
    output_dir = os.path.join(folder_path, "analysis")
    os.makedirs(output_dir, exist_ok=True)
    
    # Set plot style
    sns.set_theme(style="whitegrid")
    
    # Generate and save boxplots for each API endpoint
    for endpoint in data["Name"].unique():
        endpoint_dir = os.path.join(output_dir, endpoint.strip('/').replace('/', '_'))
        os.makedirs(endpoint_dir, exist_ok=True)
        
        subset = data[data["Name"] == endpoint]
        plot_data = []
        
        # Generate plots varying workers for each thread count
        for thread_count in subset["Threads"].unique():
            thread_subset = subset[subset["Threads"] == thread_count]
            title = f"Threads={thread_count}"
            plot_data.append((title, "Workers", thread_subset))

            plt.figure(figsize=(12, 6))
            sns.boxplot(x="Workers", y="Response Time (ms)", data=thread_subset)
            plt.title(f"Response Time Analysis for {endpoint} (Threads={thread_count})")
            plt.xlabel("Number of Workers")
            plt.ylabel("Response Time (ms)")
            # plt.yscale("log")
            # plt.gca().yaxis.set_major_formatter(ticker.ScalarFormatter())  # Use standard decimal format
            # plt.gca().yaxis.set_minor_formatter(ticker.ScalarFormatter())  # Hide minor ticks
            # plt.tick_params(axis="y", which="both", length=5)  # Ensure readable tick lengths
            # plt.tick_params(axis="y", which="both", labelsize=8)
            # plt.tick_params(axis="y", which="major", length=7)  # Make major ticks longer
            # plt.tick_params(axis="y", which="minor", length=3)  # Make minor ticks shorter


            
            # Save the plot
            plot_path = os.path.join(endpoint_dir, f"response_time_threads_{thread_count}.png")
            plt.savefig(plot_path)
            plt.close()

        plot_data.sort(key=lambda x: x[2]["Threads"].iloc[0])
        if plot_data:
            cols = 2  # Define number of columns
            rows = (len(plot_data) + 1) // cols  # Define number of rows for grid layout
            
            fig, axes = plt.subplots(rows, cols, figsize=(12, rows * 4))
            fig.suptitle(f"Response Time Analysis for {endpoint}")
            axes = axes.flatten()  # Flatten in case of single row

            for i, (title, x_label, plot_subset) in enumerate(plot_data):
                sns.boxplot(x=x_label, y="Response Time (ms)", data=plot_subset, ax=axes[i])
                axes[i].set_title(title)
                axes[i].set_xlabel(x_label)
                axes[i].set_ylabel("Response Time (ms)")
                # axes[i].set_yscale("log")

            # Remove any unused subplots in case of odd number of plots
            for j in range(i + 1, len(axes)):
                fig.delaxes(axes[j])

            
            plt.tight_layout()
            combined_plot_path = os.path.join(endpoint_dir, "response_time_threads_summary.png")
            plt.savefig(combined_plot_path)
            plt.close()

        plot_data.clear()

        # Generate plots varying threads for each worker count
        for worker_count in subset["Workers"].unique():
            worker_subset = subset[subset["Workers"] == worker_count]
            title = f"Workers={worker_count}"
            plot_data.append((title, "Threads", worker_subset))

            plt.figure(figsize=(12, 6))
            sns.boxplot(x="Threads", y="Response Time (ms)", data=worker_subset)
            plt.title(f"Response Time Analysis for {endpoint} (Workers={worker_count})")
            plt.xlabel("Number of Threads")
            plt.ylabel("Response Time (ms)")
            
            # Save the plot
            plot_path = os.path.join(endpoint_dir, f"response_time_workers_{worker_count}.png")
            plt.savefig(plot_path)
            plt.close()

        plot_data.sort(key=lambda x: x[2]["Workers"].iloc[0])
        if plot_data:
            cols = 2  # Define number of columns
            rows = (len(plot_data) + 1) // cols  # Define number of rows for grid layout
            
            fig, axes = plt.subplots(rows, cols, figsize=(12, rows * 4))
            fig.suptitle(f"Response Time Analysis for {endpoint}")
            axes = axes.flatten()  # Flatten in case of single row

            for i, (title, x_label, plot_subset) in enumerate(plot_data):
                sns.boxplot(x=x_label, y="Response Time (ms)", data=plot_subset, ax=axes[i])
                axes[i].set_title(title)
                axes[i].set_xlabel(x_label)
                axes[i].set_ylabel("Response Time (ms)")

            # Remove any unused subplots in case of odd number of plots
            for j in range(i + 1, len(axes)):
                fig.delaxes(axes[j])
            
            plt.tight_layout()
            combined_plot_path = os.path.join(endpoint_dir, "response_time_workers_summary.png")
            plt.savefig(combined_plot_path)
            plt.close()
    
    print(f"Response time analysis plots saved in {output_dir}")


def main():
    """Main function to handle script execution."""
    if len(sys.argv) != 2:
        print("Usage: python script.py <folder_path>")  # Display usage message if incorrect arguments
        sys.exit(1)
    
    folder_path = sys.argv[1]  # Get folder path from command line argument
    data = load_and_process_files(folder_path)  # Load and process all CSV files
    generate_heatmaps(data, folder_path)  # Generate heatmaps
    generate_response_time_analysis(data, folder_path)  # Generate boxplots

if __name__ == "__main__":
    main()
