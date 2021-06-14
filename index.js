//const nmapLocation  = require('node-nmap');
const http = require('http');
const path = require('path');
const fs   = require('fs');
const url  = require('url');
const nmap = require('node-nmap');
const request = require('request');
const dns = require('dns'); 


const IPAddress = {
    IP: "",
    MacAddress: "",
    hostname: "",
    Online: false,
    firstSeen: "",
    lastSeen: "",    
    Vendor: ""
  };


var token = "";
var subnet = [];
for (let i = 1; i < 255; i++) {
    var ip = Object.create(IPAddress);    
    ip.ip = "192.168.0." + i;   
    ip.MacAddress = "";
    ip.hostname = "";
    ip.Vendor = "Unknown";
    ip.Online = false;
    ip.firstSeen = "";
    ip.lastSeen = "";
    subnet.push(ip);
}


var sortTable = {sortIP: true, sortType_Asc: true, sortname_Asc: true ,sortVendor_Asc: true, sortfirstSeen_Asc: true,sortlastSeen_Asc: true };

var myArgs = process.argv.slice(2);


nmap.nmapLocation = "nmap";
var quickscan = new nmap.QuickScan("192.168.0.1/24","-sL");

quickscan.on('complete',data => {
    let currentDate = new Date().toLocaleString()

    data = data.filter(device => device.mac != null)
    //console.log(data);
    data.forEach(device => {         
        subnet.forEach(IPAddress => {
            if(device.ip == IPAddress.ip) {
                //console.log(device);
                if (IPAddress.hostname == "" && device.hostname != null) { IPAddress.hostname = device.hostname.toLowerCase() };
                if (IPAddress.MacAddress == "" && device.mac != null) { IPAddress.MacAddress =  device.mac};                
                if (IPAddress.Vendor == "Unknown" && device.vendor != null) { IPAddress.Vendor = device.vendor };
                IPAddress.Online = true;
                if (IPAddress.firstSeen == "") { IPAddress.firstSeen = currentDate};
                IPAddress.lastSeen = currentDate;           
            } ;
        });
    }); 

});

quickscan.on('error',error => {
    console.log(error);
});

setInterval(function() {
  quickscan.startScan();
  console.log("Complete - quickscan")
}, (30 * 1000));

setInterval(function() {
  //console.log(xqsystem_device_list);        
  subnet.forEach(device => {
    if(device.hostname == "") {
        dns.reverse(device.ip, (err, hostnames) => {
          if(hostnames) {
            subnet.forEach(IPAddress => {
              if(device.ip == IPAddress.ip) {
                  //console.log(device);
                  if (IPAddress.hostname == "" && device.hostname != null) { IPAddress.hostname = hostnames[0].toLowerCase() };
              } ;
            });
          }            
        });
    }    
  });
  console.log("Complete - DNS Scan")
}, (30 * 1000));



setInterval(function() {
  if(token == "") {
    var restURL = 'http://192.168.0.1/cgi-bin/luci/api/xqsystem/login?username=admin&password=' + myArgs[0];    
    request(restURL, { json: true }, (err, res, body) => {
      if (err) { return console.log(err); }
      token = body.token
    });
  } else {  
    var xqsystem_device_list;      
    request(`http://192.168.0.1/cgi-bin/luci/;stok=${token}/api/xqsystem/device_list`, { json: true }, (err, res, body) => {
    if (err) { return console.log(err); }
        //console.log(body);
        if (body.list) {
            xqsystem_device_list = body.list;
            //console.log(xqsystem_device_list);        
            let currentDate = new Date().toLocaleString()
            xqsystem_device_list.forEach(device => {            
            subnet.forEach(IPAddress => {
                if(device.ip == IPAddress.ip) {
                    if (IPAddress.hostname == "" && device.origin_name != "") { IPAddress.hostname = device.origin_name}
                    if (IPAddress.MacAddress == "" && device.mac != "") { IPAddress.MacAddress =  device.mac };
                    if (IPAddress.Vendor == "Unknown" && device.company.name != "")  { IPAddress.Vendor = device.company.name };
                    IPAddress.Online = true;
                    if (IPAddress.firstSeen == "") { IPAddress.firstSeen = currentDate};
                    IPAddress.lastSeen = currentDate;            
                    //console.log(IPAddress);
                }                  
            })  
            //console.log([device.mac,device.ip,device.hostname,device.origin_name,device.company.name]);                           
            })
            console.log("Complete - openwrt scan")
        } else {
            console.log("xqsystem_device_list is null")
        }
    });
  };
}, (30 * 1000));

const server = http.createServer((req,res) => {
    var link = url.parse(req.url, true);
    var parameters = link.query;
  
    let filePath = path.join(__dirname, link.pathname === "/" ? "nmap.html" : req.url );
  
    let contentType = "text/html";
    // Check ext and set content type
    switch (path.extname(filePath)) {
      case ".js":
        contentType = "text/javascript";
        break;
      case ".css": 
        contentType = "text/css";
        break;
      case ".json":
        contentType = "application/json";
        break;
      case ".png":
        contentType = "image/png";
        break;
      case ".jpg":
        contentType = "image/jpg";
        break;
    }
    
    if(link.pathname === '/') {
      var OutputData = [];
  
      OutputData = subnet.filter(IP => IP.MacAddress != "");
      //console.log(parameters.sort);
      switch (parameters.sort) {       
          case "name":
              OutputData = OutputData.sort(Sortname);
              sortname_Asc = ! sortname_Asc
              sortIP_Asc = true;
              sortVendor_Asc = true;
              sortfirstSeen_Asc = true;
              sortType_Asc = true;
              sortlastSeen_Asc = true;
              break;
          case "Vendor":
              OutputData = OutputData.sort(SortVendor);
              sortIP_Asc = true;
              sortname_Asc = true;
              sortType_Asc = true;
              sortVendor_Asc = ! sortVendor_Asc
              sortfirstSeen_Asc = true;
              sortlastSeen_Asc = true;
              break;
          case "ip":
              OutputData = OutputData.sort(SortIP); 
              sortIP_Asc = ! sortIP_Asc
              sortname_Asc = true;
              sortType_Asc = true;
              sortVendor_Asc = true;
              sortfirstSeen_Asc = true;
              sortlastSeen_Asc = true;
              break;
          case "firstSeen":
              OutputData = OutputData.sort(sortfirstSeen); 
              sortfirstSeen_Asc = ! sortfirstSeen_Asc;
              sortType_Asc = true;
              sortIP_Asc = true;
              sortname_Asc = true;
              sortVendor_Asc = true;
              sortlastSeen_Asc = true;
              break;
          case "type":
              OutputData = OutputData.sort(SortType); 
              sortType_Asc = ! sortType_Asc;
              sortlastSeen_Asc = true;
              sortIP_Asc = true;
              sortname_Asc = true;
              sortfirstSeen_Asc = true;
              sortVendor_Asc = true;
              break;    
          case "lastSeen":
              OutputData = OutputData.sort(sortlastSeen); 
              sortlastSeen_Asc = ! sortlastSeen_Asc;
              sortType_Asc = true;
              sortIP_Asc = true;
              sortname_Asc = true;
              sortfirstSeen_Asc = true;
              sortVendor_Asc = true;
              break;
          case "default":
              OutputData = OutputData.sort(SortIP); 
              sortIP_Asc = ! sortIP_Asc
              sortname_Asc = true;
              sortVendor_Asc = true;
              sortType_Asc = true;
              sortfirstSeen_Asc = true;
              sortlastSeen_Asc = true;
              break;
      }

      //console.log(OutputData);
      let htmlpage = '<!doctype html><html lang="en">'
      htmlpage += "<head>"
      htmlpage += '<meta charset="utf-8">'
      htmlpage += '<title>Node IP Scanner</title>'
      htmlpage += '<meta name="description" content="IP Scanner">'
      htmlpage += '<meta name="author" content="Carl Armstrong">'
      htmlpage += '<link rel="stylesheet" href="style.css">'
      htmlpage += "</head>"
      htmlpage += "<body>"
    
      if(OutputData.length > 0) {
        htmlpage += '<table id="ArmstrongAX">\n'
        htmlpage += "<tr><th><a href='/?sort=ip'>IP Address</a></th><th><a href='/?sort=name'>Name</a></th><th>MAC Address</th><th><a href='/?sort=Vendor'>Vendor</a></th><th><a href='/?sort=firstSeen'>First Seen</a></th><th><a href='/?sort=lastSeen'>Last Seen</a></th></tr>\n"
            
        OutputData.forEach(IP => {           
            var firstSeen = (new Date(IP.firstSeen).toLocaleString('en-GB')).replace(",","")
            var lastSeen = (new Date(IP.lastSeen).toLocaleString('en-GB')).replace(",","")
            
            htmlpage += `<tr><td>${IP.ip}</td><td>${IP.hostname == null ? "null" : IP.hostname.toLowerCase()}</td><td style="text-align:right">${IP.MacAddress == null ? "null" : IP.MacAddress}</td><td>${IP.Vendor}</td><td>${firstSeen}</td><td>${lastSeen}</td></tr>\n`; 
        });
        htmlpage += "</table>"      
      } else {
        htmlpage += "<H1>Initialising...</H1>"  
      }
      htmlpage += "</body>"
      htmlpage += "</html>"
    //console.log(htmlpage)
      res.writeHead(200, { 'Content-type': contentType});
      res.end(htmlpage, 'utf8')    
    } else {
    // Read File
      fs.readFile(filePath, (err, content) => {
        if (err) {
         if (err.code == "ENOENT") {
            // Page not found
            fs.readFile(
              path.join(__dirname, "public", "404.html"),
              (err, content) => {
                res.writeHead(404, { "Content-Type": "text/html" });
                res.end(content, "utf8");
              }
            );
          } else {
            //  Some server error
            res.writeHead(500);
            res.end(`Server Error: ${err.code}`);
          }
        } else {
          // Success
          res.writeHead(200, { "Content-Type": contentType });
          res.end(content, "utf8");
        }
      });
    }
  });
  
  const PORT = process.env.port || 8083;
  server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  
  var sortIP_Asc = true;
  var sortType_Asc = true;
  var sortname_Asc = true;
  var sortVendor_Asc = true;
  var sortfirstSeen_Asc = true;
  var sortlastSeen_Asc = true; 
  
  function sortfirstSeen(a,b) {
      if(a.firstSeen == null) {
          return -1
      }
      if(b.firstSeen == null) {
          return 1
      } 
      if (a.firstSeen.indexOf("/") > -1) {
          //var IPa = new Date(a.firstSeen.split('/')[1] + '-' + a.firstSeen.split('/')[0] + '-' + a.firstSeen.split('/')[2]);
          var IPa = new Date(a.firstSeen);
      } else {
          var IPa = a.firstSeen
      }
      if (b.firstSeen.indexOf("/") > -1) {
          //var IPb = new Date(b.firstSeen.split('/')[1] + '-' + b.firstSeen.split('/')[0] + '-' + b.firstSeen.split('/')[2]);
          var IPb = new Date(b.firstSeen);
      } else {
          var IPb = a.firstSeen
      }        
      if(sortfirstSeen_Asc) {
          if (IPa < IPb) {
              return -1;
          } else if (IPa > IPb) {
              return 1;
          } else {
              return 0
          }
      } else {
          if (IPa > IPb) {
              return -1;
          } else if (IPa < IPb) {
              return 1;
          } else {
              return 0
          }
      }
  }; 
  function sortlastSeen(a,b) {
      if(a.lastSeen == null) {
          return -1
      }
      if(b.lastSeen == null) {
          return 1
      }    
      if (a.lastSeen.indexOf("/") > -1) {
          //var IPa = new Date(a.lastSeen.split('/')[1] + '-' + a.lastSeen.split('/')[0] + '-' + a.lastSeen.split('/')[2]);
          var IPa = new Date(a.lastSeen);
      } else {
          var IPa = a.lastSeen
      }
      if (b.lastSeen.indexOf("/") > -1) {
          //var IPb = new Date(b.lastSeen.split('/')[1] + '-' + b.lastSeen.split('/')[0] + '-' + b.lastSeen.split('/')[2]);
          var IPb = new Date(b.lastSeen);
      } else {
          var IPb = a.lastSeen
      }    
      if(sortlastSeen_Asc) {
          if (IPa < IPb) {
              return -1;
          } else if (IPa > IPb) {
              return 1;
          } else {
              return 0
          }
      } else {
          if (IPa > IPb) {
              return -1;
          } else if (IPa < IPb) {
              return 1;
          } else {
              return 0
          }
      }
  }; 
  function SortIP(a,b) {
      if(a.ip == null) {
          return -1
      }
      if(b.ip == null) {
          return 1
      }
      if (a.ip.indexOf(".") > -1) {
          var IPa = Number(a.ip.split(".")[3]);
      } else {
          var IPa = a.ip
      }
      if (b.ip.indexOf(".") > -1) {
          var IPb = Number(b.ip.split(".")[3]);
      } else {
          var IPb = b.ip
      }    
      if(sortIP_Asc) {
          if (IPa < IPb) {
              return -1;
          } else if (IPa > IPb) {
              return 1;
          } else {
              return 0
          }
      } else {
          if (IPa > IPb) {
              return -1;
          } else if (IPa < IPb) {
              return 1;
          } else {
              return 0
          }
      }
  }; 
  function Sortname(a,b) {
      if(sortname_Asc) {
          if (a.hostname > b.hostname) {
              return 1;
          } else if (a.hostname < b.hostname) {
              return -1;
          } else {
              return 0;
          }
      } else {
          if (a.hostname < b.hostname) {
              return 1;
          } else if (a.hostname > b.hostname) {
              return -1;
          } else {
              return 0;
          }
      }
  };
  function SortType(a,b) {
      if(sortType_Asc) {
          if (a.type > b.type) {
              return 1;
          } else if (a.type < b.type) {
              return -1;
          } else {
              return 0;
          }
      } else {
          if (a.type < b.type) {
              return 1;
          } else if (a.type > b.type) {
              return -1;
          } else {
              return 0;
          }
      }
  };
  function SortVendor(a,b) {
      if (sortVendor_Asc) {
          if (a.Vendor < b.Vendor) {
              return -1;
          } else if (a.Vendor > b.Vendor) {
              return 1;
          } else {
              return 0;
          }
      } else {
          if (a.Vendor > b.Vendor) {
              return -1;
          } else if (a.Vendor < b.Vendor) {
              return 1;
          } else {
              return 0;
          }                
      }
  };
  
