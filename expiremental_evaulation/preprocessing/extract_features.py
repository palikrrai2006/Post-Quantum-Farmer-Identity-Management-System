import cv2
import numpy as np
import time

from tensorflow.keras.applications.mobilenet_v2 import (
    MobileNetV2,
    preprocess_input
)

model = MobileNetV2(
    weights="imagenet",
    include_top=False,
    pooling="avg"
)

def extract_features(input_image, output_template):

    img = cv2.imread(input_image)

    img = cv2.resize(img, (224,224))

    img = np.expand_dims(img, axis=0)

    img = preprocess_input(img)

    start = time.time()

    features = model.predict(img, verbose=0)

    end = time.time()

    print(
        "Feature Extraction Time:",
        (end-start)*1000,
        "ms"
    )

    np.save(output_template, features)

    print("Template Saved")


if __name__ == "__main__":

    extract_features(
        "gabor_fingerprint.png",
        "template.npy"
    )