from pytube import YouTube
from youtube_transcript_api import YouTubeTranscriptApi
from langchain_openai import OpenAI
from langchain.text_splitter import CharacterTextSplitter
from langchain.chains.summarize import load_summarize_chain
from langchain.schema import Document
import os
import openai
import requests

openai.api_key = os.getenv("OPENAI_API_KEY")


def summarize_video(url):
    try:
        print(f"Procesando la URL: {url}")
        video_id = url.split("v=")[-1]
        transcript = YouTubeTranscriptApi.get_transcript(video_id, languages=['en'])

        transcript_text = " ".join([entry['text'] for entry in transcript])

        text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
        split_texts = text_splitter.split_text(transcript_text)

        documents = [Document(page_content=text) for text in split_texts]

        llm = OpenAI(temperature=0.7, max_tokens=500)
        chain = load_summarize_chain(llm, chain_type="map_reduce")

        summary = chain.invoke({"input_documents": documents})

        send_whatsapp_message(url, summary)

    except Exception as e:
        print(f"Ups!, Ocurrió un error: {e}")


def send_whatsapp_message(url, message):
    api_key = os.getenv("CALLMEBOT_API_KEY")  # Reemplaza con tu API Key obtenida de CallMeBot
    phone_number = os.getenv("MY_PHONE_NUMBER")  # Tu número de WhatsApp con código de país, por ejemplo:  +1234567890
    text_message = f"resume from {url}\n{message['output_text']}"  # El mensaje que se va a enviar

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
    url = input("Ingresa la URL del video de YouTube: ")
    summarize_video(url)
