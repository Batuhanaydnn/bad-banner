import tweepy
import time
import openai

# Twitter API kimlik bilgileri
twitter_auth = {
    "consumer_key": "YOUR_CONSUMER_KEY",
    "consumer_secret": "YOUR_CONSUMER_SECRET",
    "access_token": "YOUR_ACCESS_TOKEN",
    "access_token_secret": "YOUR_ACCESS_TOKEN_SECRET"
}

# OpenAI GPT-3 API anahtarı
openai.api_key = "YOUR_OPENAI_API_KEY"


class TwitterAPI:
    def __init__(self, auth_info):
        auth = tweepy.OAuthHandler(
            auth_info["consumer_key"], auth_info["consumer_secret"])
        auth.set_access_token(
            auth_info["access_token"], auth_info["access_token_secret"])
        self.api = tweepy.API(auth)

    def tweet(self, text):
        self.api.update_status(text)
        # Her tweet arasında 3 saniye bekleyin, Twitter API sınırlamalarını aşmamak için
        time.sleep(3)


class TextSplitter:
    def __init__(self, max_length):
        self.max_length = max_length

    def split_text_into_parts(self, text):
        parts = []
        current_part = ""

        words = text.split()

        for word in words:
            if len(current_part) + len(word) + 1 <= self.max_length - 2:
                current_part += word + " "
            else:
                parts.append(current_part + "++")
                current_part = word + " "

        if current_part:
            parts.append(current_part + "++")

        return parts


class ArticleGenerator:
    def generate_article(self, topic):
        response = openai.Completion.create(
            engine="davinci",
            prompt=f"3600 kelimelik bir makale hazırla: {topic}",
            max_tokens=3600,
            stop="++"
        )
        return response.choices[0].text.strip()


def main():
    topic = input("Makale konusunu girin: ")

    article_generator = ArticleGenerator()
    article = article_generator.generate_article(topic)

    with open("metin.txt", "w", encoding="utf-8") as file:
        file.write(article)

    twitter = TwitterAPI(twitter_auth)
    splitter = TextSplitter(max_length=240)
    parts = splitter.split_text_into_parts(article)

    # Parçaları Twitter'da flood olarak paylaşma işlemi
    for i, part in enumerate(parts):
        tweet = f"Parça {i+1}: {part}"
        twitter.tweet(tweet)
        print(f"Tweet atıldı: {tweet}")


if __name__ == "__main__":
    main()
