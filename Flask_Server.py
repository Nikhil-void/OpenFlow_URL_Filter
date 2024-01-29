import json
from flask import Flask, request, jsonify

# Using flask to make an api
# import necessary libraries and functions
from flask import Flask, jsonify, request

# creating a Flask app
app = Flask(__name__)

# We maintain a list of bad web domains in file
with open("bad_website_list.txt") as fp:
    website_data = fp.readlines()

print("Bad Websites Are: ", website_data) 

# Below function acts as a site checker rest api application and returns 'good' or 'bad' as json based on status 
@app.route('/site_checker', methods = ['GET'])
def site_check():
    website = request.query_string.decode()
    
    status = "good"
    for i in website_data:
        if website in i:
            status = "bad"
    return jsonify({'status': status})

# Below function is used as the home page of this webserver, it displays a "Bad website" warning message if clients connets to it
@app.route('/', methods = ['GET'])
def bad_page():
    return """
<!DOCTYPE html>
<html>
<head>
<title>Page Title</title>
</head>
<body>

<h1>Warning: Bad Website</h1>
<p>This website is regarded as Bad Website by your Admin.</p>

</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug = True, host = "0.0.0.0", port = "80")
