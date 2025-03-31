# Web Application Security Scanner
This Python script is designed to detect vulnerabilities in web applications. 
It analyzes and tests common vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS) and Insecure Direct Object References (IDOR).
It also reports vulnerabilities by examining various components on the web page, such as forms and GET parameters. 
The user can save data in different file formats (txt, json, csv).
# Features
* URL Parameter Analysis: Analyzes and detects parameters in the URL.

* Form Data Extraction: Collects HTML form data and analyzes form elements.

* SQLi Testing: Tests for SQL injection (SQLi) vulnerabilities in URLs on the web page.

* XSS Testing: Tests for Cross-Site Scripting (XSS) vulnerabilities in both URLs and HTML forms.

* IDOR Testing: Tests for Insecure Direct Object Reference (IDOR) vulnerabilities.

* Reporting: Saves the found data in txt, json or csv formats.

> Requirements
* Python 3.x

* requests library

* BeautifulSoup library (for HTML parsing)

* urllib (for URL processing)

* json and csv (for data saving)
  
> These libraries can be installed with the following command:

`$pip install requests beautifulsoup4`

# Use
> Run the script:
`python app.py`
1-Enter URL: Enter the URL of the website you want to test. Make sure you type the URL in the correct format (for example, https://example.com).

2-Perform Security Tests: The script automatically launches tests such as SQLi, XSS and IDOR. Each test reports the vulnerabilities detected.

3-Select Data Saving Options:

4-Select the file formats you want to save (txt, json, csv).

5-The data will be saved in the specified folder in the format you selected.

6-Results: The script saves the data in the specified file formats and shows you the results of each test.

>Saving Formats

>>Data can be saved in the following formats:

* TXT: Raw data is saved with headings and results for each section.

* JSON: All data is saved in organized JSON format.

* CSV: Data is saved in CSV format with columns containing the results of each safety test.

> Sample Outputs
* SQL Injection Test: Shows the URL and related parameter where SQL injection vulnerability was detected.

* XSS Testing: Reports detected XSS vulnerabilities, which payloads were successful and which URLs were affected.

* IDOR Test: Lists the URLs where IDOR vulnerabilities were detected and the unauthorized access status.

> File Structure
>> When the script is run, the following file structure will be created:

```
/veriler
    veriler.txt
    veriler.json
    veriler.csv

```
# License
# This software is licensed under the MIT License.
# I take no responsibility for any illegal use. Try it only when testing your own web site security!!!

