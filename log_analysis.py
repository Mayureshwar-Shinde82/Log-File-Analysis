from collections import Counter
import csv

class LogFileAnalysis():
    
    def __init__(self,file_path,output_file_path):
        self.file_path = file_path
        self.parse_log_file(file_path)
        self.save_to_csv(output_file_path)
        
    def parse_log_file(self,file_path):
        """Parse the log file and extract relevant data."""
        
        with open(file_path,'r') as file:
            lines = file.readlines()

        lst = []
        self.endpoint = []
        failed_attempts = []

        for line in lines:
            parts = line.split()
            self.endpoint.append(parts[6])
            lst.append(parts[0])
            if '401' in parts:
                failed_attempts.append(parts[0])
                
        ip_add_dict = Counter(lst)         
        self.ip_address = dict(sorted(ip_add_dict.items(), key = lambda x:x[1], reverse=True))
        print("Requests per IP Address:")
        for ip_add,count in self.ip_address.items():
            print(f"{ip_add},{count}")
            
        self.failed_login_attempts = dict(Counter(failed_attempts))
        
        self.most_frequently_accessed_endpoint(self.endpoint)
        self.detect_suspicious_activity(self.failed_login_attempts)
        
    def most_frequently_accessed_endpoint(self,endpoint):
        """Identify the most accessed endpoint."""
        
        count = 1
        most_accessed_endpoint = endpoint[0]
        for i in endpoint:
            if endpoint.count(i) > count:
                most_accessed_endpoint = i
                count = endpoint.count(i)
        print("\nMost Frequently Accessed Endpoint:")
        print(most_accessed_endpoint,",",count)
        return [most_accessed_endpoint,count]
    
    
    def detect_suspicious_activity(self,failed_login_attempts):
        """Identify suspicious IPs exceeding the failed login threshold."""
        
        print("\nSuspicious Activity Detected:")
        for ip_add,count in failed_login_attempts.items():
            print(f"{ip_add},{count}")
            
            
    def save_to_csv(self,output_file_path):
        """Save the analysis results to a CSV file."""
        
        with open(output_file_path, 'w', newline='') as csv_file:
            writer = csv.writer(csv_file)
            
            writer.writerow(["Count Requests per IP Address:"])
            writer.writerow(["IP Address","Request Count"])
            for ip_add,count in self.ip_address.items():
                writer.writerow([ip_add,count])
            
            writer.writerow([])
            writer.writerow(["Most Frequently Accessed Endpoint:"])
            writer.writerow(["Endpoint","Access Count"])
            endpoint = self.most_frequently_accessed_endpoint(self.endpoint)
            writer.writerow([endpoint[0],endpoint[1]])
            
            writer.writerow([])
            writer.writerow(["Suspicious Activity Detected:"])
            writer.writerow(["IP Address", "Failed Login Attempts"])
            for ip_add,count in self.failed_login_attempts.items():
                writer.writerow([ip_add,count])


if __name__ == '__main__':
    file_path = 'sample.log'
    output_file_path = 'log_analysis_results.csv'
    object = LogFileAnalysis(file_path,output_file_path)