from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import concurrent.futures
import re
import sqlite3
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from googlesearch import search
from gensim.models import Word2Vec, FastText
from sklearn.decomposition import TruncatedSVD
from sklearn.preprocessing import normalize
import numpy as np
from collections import Counter
from wordcloud import WordCloud
import matplotlib.pyplot as plt

# Veritabanına bağlan
conn = sqlite3.connect('search_results.db')
cursor = conn.cursor()

# Tabloyu oluştur
cursor.execute('''
    CREATE TABLE IF NOT EXISTS search_results (
        id INTEGER PRIMARY KEY,
        query TEXT,
        result TEXT
    )
''')
conn.commit()

def clean_text(text):
    cleaned_text = re.sub('<.*?>', '', text)
    cleaned_text = re.sub('\s+', ' ', cleaned_text)
    return cleaned_text.strip()

def fetch_search_results_from_db(query):
    cursor.execute('SELECT result FROM search_results WHERE query = ?', (query,))
    results = cursor.fetchall()
    return [result[0] for result in results]

def train_and_predict_model(X, y, new_query):
    vectorizer = CountVectorizer()
    X_vectorized = vectorizer.fit_transform(X)

    model = MultinomialNB()
    model.fit(X_vectorized, y)

    new_query_cleaned = clean_text(new_query)
    new_query_vectorized = vectorizer.transform([new_query_cleaned])
    predicted_label = model.predict(new_query_vectorized)

    return predicted_label[0]

def search_and_store_results(query):
    search_results = list(search(query, num_results=10, lang='tr'))
    for result in search_results:
        cursor.execute('INSERT INTO search_results (query, result) VALUES (?, ?)', (query, result))
    conn.commit()

def build_search_tree():
    search_tree = {}
    for query in queries:
        results = fetch_search_results_from_db(query)
        search_tree[query] = results
    return search_tree

def perform_deep_search(keyword):
    deep_search_results = list(search(keyword, num_results=20, lang='tr'))
    return deep_search_results

def analyze_contexts(search_tree):
    contexts = {}

    for keyword, results in search_tree.items():
        keyword_contexts = []

        for result in results:
            cleaned_result = clean_text(result)
            
            # Word2Vec veya FastText modelini eğitme
            sentences = [cleaned_result.split()]
            w2v_model = Word2Vec(sentences, vector_size=300, window=5, min_count=1, sg=1, epochs=50)
            
            # Kelimelerin vektörlerini alarak kümelenme işlemi
            word_vectors = [w2v_model.wv[word] for word in cleaned_result.split() if word in w2v_model.wv]
            num_clusters = 5
            kmeans = KMeans(n_clusters=num_clusters, init='k-means++', n_init=10, max_iter=300, random_state=42)
            kmeans.fit(word_vectors)
            
            cluster_labels = kmeans.labels_
            cluster_centers = kmeans.cluster_centers_
            
            svd = TruncatedSVD(n_components=2)
            cluster_centers_reduced = svd.fit_transform(cluster_centers)
            cluster_centers_reduced = normalize(cluster_centers_reduced, norm='l2', axis=1)
            
            terms = list(w2v_model.wv.index_to_key)
            sorted_indices = np.argsort(cluster_centers, axis=1)[:, ::-1]
            top_terms_per_cluster = [terms[ind] for ind in sorted_indices]
            
            # Anahtar kelimenin bağlamını en sık kullanılan terimlerle görselleştirin
            all_words = ' '.join(cleaned_result.split())
            word_freq = Counter(all_words.split())
            wordcloud = WordCloud(width=800, height=400, background_color='white').generate_from_frequencies(word_freq)
            
            # Kelime vektörlerinin görselleştirilmesi
            plt.figure(figsize=(10, 6))
            for i, label in enumerate(cluster_labels):
                plt.scatter(cluster_centers_reduced[i, 0], cluster_centers_reduced[i, 1], marker=f'${label}$', s=300, label=f'Cluster {label}')
            plt.title(f'Word Vectors Clustering for "{keyword}" Context')
            plt.xlabel('Truncated SVD Component 1')
            plt.ylabel('Truncated SVD Component 2')
            plt.legend()
            plt.grid(True)
            plt.show()
            
            keyword_contexts.append({
                'result': result,
                'cluster_labels': cluster_labels,
                'cluster_centers_reduced': cluster_centers_reduced,
                'top_terms_per_cluster': top_terms_per_cluster,
                'wordcloud': wordcloud
            })
        
        contexts[keyword] = keyword_contexts

    return contexts

def main():
    queries = ["Cybersecurity", "Python programming", "Machine learning"]
    num_workers = len(queries)

    for query in queries:
        search_and_store_results(query)

    results = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_query = {executor.submit(fetch_search_results_from_db, query): query for query in queries}
        for future in concurrent.futures.as_completed(future_to_query):
            query = future_to_query[future]
            try:
                query_results = future.result()
                results[query] = query_results
            except Exception as exc:
                print(f'Hata oluştu: {exc}')

    # Sonuçları temizle ve düzenle
    cleaned_results = {}
    for query, query_results in results.items():
        cleaned_query_results = [clean_text(result) for result in query_results]
        cleaned_results[query] = cleaned_query_results

    # Veri ve etiketleri oluştur
    X = []
    y = []
    for query, query_results in cleaned_results.items():
        X.extend(query_results)
        y.extend([query] * len(query_results))

    # Ağaç oluşturma
    search_tree = build_search_tree()

    # Yeni bir sorgu ile tahmin yapma
    new_query = "What is Python used for?"
    predicted_label = train_and_predict_model(X, y, new_query)

    print(f"Sorgu: {new_query}")
    print(f"Tahmin edilen etiket: {predicted_label}")
    print("Arama Ağacı:")
    print(search_tree)

    # Metin madenciliği ve bağlam analizi
    contexts = analyze_contexts(search_tree)

    # İlgili bağlamı döndürme
    relevant_context = contexts.get(predicted_label, "Bağlam bulunamadı.")
    print("İlgili Bağlam:")
    print(relevant_context)

    # Derinlemesine arama ve ilgili sonuçları bulma
    deep_search_results = perform_deep_search(predicted_label)
    print("Derinlemesine Arama Sonuçları:")
    print(deep_search_results)

if __name__ == "__main__":
    main()
