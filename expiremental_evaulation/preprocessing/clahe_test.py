import cv2
import time

def run_clahe(input_image, output_image):

    img = cv2.imread(
        input_image,
        cv2.IMREAD_GRAYSCALE
    )

    start = time.time()

    clahe = cv2.createCLAHE(
        clipLimit=2.0,
        tileGridSize=(8,8)
    )

    enhanced = clahe.apply(img)

    end = time.time()

    print("CLAHE Time:", (end-start)*1000, "ms")

    cv2.imwrite(output_image, enhanced)

    print("Image Saved")


if __name__ == "__main__":
    run_clahe(
        r"dataset\SOCOFing\Real\1__M_Left_index_finger.BMP",
        "enhanced_fingerprint.png"
    )