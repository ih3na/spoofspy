import streamlit as st
import sniff

data = []

while not (sniff.captured_data.empty()):
    data.append(sniff.captured_data.get())
    for unit in data:
        st.write(str(unit))
