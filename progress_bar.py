import sys

class ProgressBar:
    def __init__(self, total, description="Progress"):
        self.total = total
        self.current = 0
        self.description = description
        self.bar_length = 50
        
    def update(self, increment=1):
        self.current += increment
        self.draw()
        
    def draw(self):
        filled_length = int(self.bar_length * self.current // self.total)
        bar = '█' * filled_length + '-' * (self.bar_length - filled_length)
        percent = 100 * self.current // self.total
        sys.stdout.write(f'\r{self.description}: [{bar}] {percent}% ({self.current}/{self.total})')
        sys.stdout.flush()
        
    def finish(self):
        self.current = self.total
        self.draw()
        print()  # New line after progress bar
