import os
import cv2
import numpy as np

from tensorflow.keras.applications.mobilenet_v2 import (
    MobileNetV2,
    preprocess_input
)

model = MobileNetV2(
    weights="imagenet",
    include_top=False,
    pooling="avg"
)

image_folder = "../dataset/test_100"
template_folder = "../templates"

os.makedirs(template_folder, exist_ok=True)

for image_name in os.listdir(image_folder):

    image_path = os.path.join(image_folder, image_name)

    img = cv2.imread(image_path)

    if img is None:
        continue

    img = cv2.resize(img, (224,224))

    img = np.expand_dims(img, axis=0)

    img = preprocess_input(img)

    features = model.predict(img, verbose=0)

    template_name = image_name.split(".")[0] + ".npy"

    np.save(
        os.path.join(template_folder, template_name),
        features
    )

    print("Saved:", template_name)

print("All templates generated")