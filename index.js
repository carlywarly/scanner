//const nmapLocation  = require('node-nmap');
const http = require('http');
const path = require('path');
const fs   = require('fs');
const url  = require('url');
const nmap = require('node-nmap');
const request = require('request');
const dns = require('dns');
const loki = require('lokijs')

var db = new loki('.NetScan.json');

var ipAddresses
var macAddresses

var omadaUser = process.env.omadaUser || "admin";
var omadaPass = process.env.omadaPass;


db.loadDatabase({}, function(err) {
    if (err) {
      console.log("error : " + err);
    }
    else {
      //console.log(db.listCollections())
      macAddresses = db.getCollection("mac");
      if (macAddresses === null) {
        macAddresses = db.addCollection('mac', { indices: ['mac'] });
      }
      ipAddresses = db.getCollection("ip");
      if (ipAddresses === null) {
        ipAddresses  = db.addCollection('ip', { indices: ['ip','mac'] });
      }
      console.log("database loaded.");
    }
});

// IP - ip,mac,hostname
// MAC - mac,vendor,firstseen,lastseen,hostname

var token = "";
var subnet = [];

var cookieJar = request.jar();

var quickscan = new nmap.QuickScan("192.168.0.1/24","-sn");

quickscan.on('complete',data => {
    console.log("Quickscan data load");

    let currentDate = new Date().toLocaleString()

    if(typeof ipAddresses !== 'undefined') {
        data = data.filter(device => device.mac != null)
        //console.log(data);
        data.forEach(device => {         
            var entry = ipAddresses.findOne({ ip:device.ip });
            if(entry == null ) {
                //console.log("IP: " + device.ip);
                ipAddresses.insert( { 
                    ip : device.ip, 
                    mac: device.mac, 
                    hostname: (device.hostname == null ? "" : device.hostname.toLowerCase()), 
                    vendor: device.vendor,
                    firstSeen: currentDate,
                    lastSeen: currentDate
                    } );
            } else {
                //console.log("Found: " + device.ip);
                entry.mac = device.mac;
                entry.hostname = device.hostname;
                entry.vendor = device.vendor;
                entry.lastSeen = currentDate;
                ipAddresses.update(entry);
            };
            var macEntry = macAddresses.findOne({ mac:device.mac });
            if(macEntry == null ) {
                //console.log("MAC: " + device.mac);
                macAddresses.insert( { 
                    mac: device.mac, 
                    vendor: device.vendor,
                    } );
            };
        }); 
        db.saveDatabase();
    };
});


if(omadaPass != "") {    
    setInterval(function() {
        if(token == "") {
            var options = {
                url: 'https://192.168.0.20:8043/api/v2/login',
                json: true,
                rejectUnauthorized: false,
                requestCert: true,                
                method: "POST",
                jar: cookieJar,
                body: {
                    username: omadaUser,
                    password: omadaPass
                }
            };
            //console.log(options);
            request(options, (err, res, response) => {
                if (err) { return console.log(err); }
                token = response.result.token
                console.log(token);

            });
        } else {  
            var options = {
                url: 'https://192.168.0.20:8043/api/v2/sites/Default/clients?currentPage=1&currentPageSize=100&filters.active=true&token=' + token,
                json: true,
                rejectUnauthorized: false,
                requestCert: true,                
                jar: cookieJar,
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                method: "GET"
            };
            //console.log(options);
            request(options, (err, res, response) => {
                if (err) { return console.log(err); }
                console.log(`statusCode: ${res.statusCode}`)
                
                if (response) {
                    client_list = response.result.data;
                    //console.log(xqsystem_device_list);        
                    let currentDate = new Date().toLocaleString()
                    client_list.forEach(device => {            
                        subnet.forEach(IPAddress => {
                            if(device.ip == IPAddress.ip) {
                                if (IPAddress.hostname == "" && device.hostname != "") { IPAddress.hostname = device.hostname}
                                if (IPAddress.MacAddress == "" && device.mac != "") { IPAddress.MacAddress =  device.mac };
                                IPAddress.Online = true;
                                if (IPAddress.firstSeen == "") { IPAddress.firstSeen = currentDate};
                                IPAddress.lastSeen = currentDate;            
                                //console.log(IPAddress);
                            }                  
                        })  
                        //console.log([device.mac,device.ip,device.hostname,device.origin_name,device.company.name]);                           
                    })
                    console.log("Complete - omada scan")
                } else {
                    console.log("omada is null")
                }
            });

        };
    }, (30 * 1000));
};


quickscan.on('error',error => {
    console.log(error);
});
function isEmpty(val){
    return (val === undefined || val == null || val.length <= 0) ? true : false;
}

setInterval(function() {    
    db.saveDatabase(function(err) {
        if (err) {
            console.log("error : " + err);
        }
        else {
            console.log("database saved.");
        }
    });
}, (120 * 1000));
  

setInterval(function() {    
    if(typeof macAddresses !== 'undefined') {
        var results = macAddresses.where(function(obj) {
            return (! obj.mac);
        });
        console.log(results);
    }
}, (90 * 1000));    


setInterval(function() {
  //quickscan = new nmap.QuickScan("192.168.0.1/24","-sL");
  quickscan.startScan();
  console.log("Complete - quickscan")
}, (90 * 1000));

setInterval(function() {  
  var results = ipAddresses.where(obj => {
    return obj.hostname == "";
  });
  
  results.forEach(device => {    
    dns.reverse(device.ip, (err, hostnames) => {
        if(hostnames != null) {
            var entry = ipAddresses.findOne({ ip:device.ip });
            if(entry != null ) {
                entry.hostname = hostnames.join("");
                ipAddresses.update(entry);
            };
        }            
    });
  });
  console.log("Complete - DNS Scan")
}, (90 * 1000));


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
  
      var OutputData = ipAddresses.data;
      
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
    
      htmlpage += '<table id="ArmstrongAX">\n'
      htmlpage += "<tr><th><a href='/?sort=ip'>IP Address</a></th><th><a href='/?sort=name'>Name</a></th><th>MAC Address</th><th><a href='/?sort=Vendor'>Vendor</a></th><th><a href='/?sort=firstSeen'>First Seen</a></th><th><a href='/?sort=lastSeen'>Last Seen</a></th></tr>\n"
          
      OutputData.forEach(IP => {           
          htmlpage += `<tr><td>${IP.ip}</td><td>${IP.hostname == null ? "" : IP.hostname.toLowerCase()}</td><td style="text-align:right">${IP.mac == null ? "null" : IP.mac}</td><td>${IP.vendor}</td><td>${IP.firstSeen}</td><td>${IP.lastSeen}</td></tr>\n`;                  
      });
      htmlpage += "</table>"      
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
  
  const PORT = process.env.port || 8081;
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
          var IPa = new Date(a.firstSeen.split('/')[1] + '-' + a.firstSeen.split('/')[0] + '-' + a.firstSeen.split('/')[2]);
      } else {
          var IPa = a.firstSeen
      }
      if (b.firstSeen.indexOf("/") > -1) {
          var IPb = new Date(b.firstSeen.split('/')[1] + '-' + b.firstSeen.split('/')[0] + '-' + b.firstSeen.split('/')[2]);
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
          var IPa = new Date(a.lastSeen.split('/')[1] + '-' + a.lastSeen.split('/')[0] + '-' + a.lastSeen.split('/')[2]);
      } else {
          var IPa = a.lastSeen
      }
      if (b.lastSeen.indexOf("/") > -1) {
          var IPb = new Date(b.lastSeen.split('/')[1] + '-' + b.lastSeen.split('/')[0] + '-' + b.lastSeen.split('/')[2]);
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
          if (a.vendor < b.vendor) {
              return -1;
          } else if (a.vendor > b.vendor) {
              return 1;
          } else {
              return 0;
          }
      } else {
          if (a.vendor > b.vendor) {
              return -1;
          } else if (a.vendor < b.vendor) {
              return 1;
          } else {
              return 0;
          }                
      }
  };
  
