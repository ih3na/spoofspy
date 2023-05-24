from fastapi import FastAPI, Request
import subprocess as sp
import sniff as sf

app = FastAPI()

cmd = "sudo python3 sniff.py"
sp.run(cmd, shell=True)


@app.get("/")
async def root():

    return sf.captured_data.get()

# @app.get("/stats")
# def index(request: Request):
#     data = []
#     while not captured_data.empty():
#         data.append(captured_data.get())
#     return {"request": request, "interface": expected_interface, "data": data}

# @app.post("/")
# async def update_interface(request: Request):
#     form = await request.form()
#     global expected_interface
#     expected_interface = form["interface"]
#     return {"message": "Interface updated successfully"}

