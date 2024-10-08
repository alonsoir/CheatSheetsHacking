from pytube import YouTube
from youtube_transcript_api import YouTubeTranscriptApi
from langchain_openai import OpenAI
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains.summarize import load_summarize_chain
from langchain.schema import Document
import os
import openai
import requests
from fastapi import FastAPI

openai.api_key = os.getenv("OPENAI_API_KEY")
app = FastAPI()

@app.get("/api/summarize_video")
def summarize_video(url: str):  # Accepting 'url' as a query parameter
    try:
        documents = create_summarized_doc_from_url(url)

        chain = initialize_llm()

        summary = chain.invoke({"input_documents": documents})

        send_whatsapp_message(url, summary)

        return {"summary": summary['output_text']}  # Returning the summary as JSON response

    except Exception as e:
        print(f"Ups!, Ocurrió un error: {e}")
        return {"error": str(e)}  # Returning error message as JSON response

def initialize_llm():
    llm = OpenAI(temperature=0.7, max_tokens=500)
    chain = load_summarize_chain(llm, chain_type="map_reduce")
    return chain

def create_summarized_doc_from_url(url):
    print(f"Procesando la URL: {url}")
    video_id = url.split("v=")[-1]
    transcript = YouTubeTranscriptApi.get_transcript(video_id, languages=['en'])
    transcript_text = " ".join([entry['text'] for entry in transcript])
    text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    split_texts = text_splitter.split_text(transcript_text)
    documents = [Document(page_content=text) for text in split_texts]
    return documents

def send_whatsapp_message(url, message):
    api_key = os.getenv("CALLMEBOT_API_KEY")  # Reemplaza con tu API Key obtenida de CallMeBot
    phone_number = os.getenv("MY_PHONE_NUMBER")  # Tu número de WhatsApp con código de país, por ejemplo: +1234567890
    text_message = f"Resume from {url}\n{message['output_text']}"  # El mensaje que se va a enviar

    callmebot_url = f"https://api.callmebot.com/whatsapp.php?phone={phone_number}&text={text_message}&apikey={api_key}"

    try:
        response = requests.get(callmebot_url)
        if response.status_code == 200:
            print("Mensaje enviado correctamente a WhatsApp.")
        else:
            print(f"Error al enviar el mensaje: {response.status_code}")
    except Exception as e:
        print(f"Ups! Ocurrió un error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)  # Run the FastAPI app