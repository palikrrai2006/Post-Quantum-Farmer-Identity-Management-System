import cv2
import numpy as np
import time

def run_gabor(input_image, output_image):

    img = cv2.imread(
        input_image,
        cv2.IMREAD_GRAYSCALE
    )

    start = time.time()

    kernel = cv2.getGaborKernel(
        (21,21),
        5,
        np.pi/4,
        10,
        0.5,
        0,
        ktype=cv2.CV_32F
    )

    filtered = cv2.filter2D(
        img,
        cv2.CV_8UC3,
        kernel
    )

    end = time.time()

    print("Gabor Time:", (end-start)*1000, "ms")

    cv2.imwrite(output_image, filtered)

    print("Gabor Image Saved")


if __name__ == "__main__":
    run_gabor(
        "enhanced_fingerprint.png",
        "gabor_fingerprint.png"
    )