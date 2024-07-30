import json
import sys
import bencodepy
import hashlib

def decode_bencode(bencoded_value):
    first_char = chr(bencoded_value[0])
    if first_char.isdigit():
        length_end = bencoded_value.find(b":")
        length = int(bencoded_value[:length_end])
        start = length_end + 1
        return bencoded_value[start:start + length]
    elif first_char == "i":
        end = bencoded_value.find(b"e")
        return int(bencoded_value[1:end])
    elif first_char == "l" or first_char == "d":
        return bencodepy.decode(bencoded_value)
    else:
        raise NotImplementedError("Only strings, integers, lists, and dictionaries are supported at the moment")

def main():
    if len(sys.argv) < 3:
        print("Usage: python script.py <command> <value>")
        return
    
    command = sys.argv[1]
    
    def bytes_to_str(data):
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        elif isinstance(data, int):
            return data
        elif isinstance(data, list):
            return [bytes_to_str(item) for item in data]
        elif isinstance(data, dict):
            return {
                bytes_to_str(key): bytes_to_str(value) for key, value in data.items()
            }
        else:
            raise TypeError(f"Type not serializable: {type(data)}")
    
    if command == "decode":
        bencoded_value = sys.argv[2].encode()
        decoded_value = decode_bencode(bencoded_value)
        print(json.dumps(decoded_value, default=bytes_to_str))
    
    elif command == "info":
        file_path = sys.argv[2]
        with open(file_path, "rb") as file:
            content = file.read()
        
        decoded_content = bencodepy.decode(content)
        data = bytes_to_str(decoded_content)
        
        print(f'Tracker URL: {data["announce"]}')
        print(f'Length: {data["info"]["length"]}')
        info_hash = hashlib.sha1(bencodepy.encode(decoded_content[b"info"])).hexdigest()
        print(f'Info Hash: {info_hash}')
        print(f'Piece Length: {data["info"]["piece length"]}')
        print("Piece Hashes: ")
        
        for i in range(0, len(decoded_content[b"info"][b"pieces"]), 20):
            print(decoded_content[b"info"][b"pieces"][i : i + 20].hex())
    
    else:
        raise NotImplementedError(f"Unknown command {command}")

if __name__ == "__main__":
    main()
