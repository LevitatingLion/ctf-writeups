# Captcha

For this challenge we are provided with the URL of a website `http://hax1.allesctf.net:9200/`. The site prompts us to solve a series of CAPTCHAs, in a total of four levels. The first two levels consist of one and three captchas and can be solved by hand, while levels three and four consist of ten and one hundred captchas with a time limit of thirty seconds.

Looking at how the captchas are received from and the solutions sent to the server, I couldn't find any bugs. The intended solution is probably to build something to automatically solve these captchas; that also fits with the challenge being in the 'misc' category instead of 'web'. The letters in the captcha images are not too distorted, so this should well be possible.

I'll divide the problem of solving these captchas in two smaller problems and tackle them individually. First, splitting the captcha into the individual letters; this will be done by processing the image with OpenCV. Second, recognizing the letters; this will be done by a convolutional neural network with Keras.

I'm skipping over the part of talking to the webserver. If you're interested in that, you can find it in the full code listing at the end of this writeup.

## Splitting into Letters

For this subproblem, we are given a captcha image which we want to split into images of letters.

We start by thresholding the (already grayscale) image, to obtain a black and white image.

```py
img = cv2.threshold(img, 80, 255, cv2.THRESH_BINARY_INV)[1]
```

Now, we can apply OpenCV's `findContours` function to find all connected regions.

```py
contours = cv2.findContours(img, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)[0]
```

Since the pointset returned by OpenCV is difficult to work with, we convert it into a list of `x, y, w, h` of the bounding rectangles of each region. Because two letters in the captcha image may touch or partly overlap, we also split very wide regions into two in this step.

```py
regions = []
for contour in contours:
    x, y, w, h = cv2.boundingRect(contour)
    if w / h > 1.35:
        w //= 2
        regions.append((x, y, w, h))
        regions.append((x + w, y, w, h))
    else:
        regions.append((x, y, w, h))
```

One last problem with the regions remains: when encountering a small `i`, we will have one region for its body and one for its dot. To solve this, we merge regions which touch vertically and partly overlap horizontally.

```py
# sort by x coordinate
regions.sort(key=lambda r: r[0])

# determine which regions to merge
to_merge = []
for i, (r1, r2) in enumerate(zip(regions, regions[1:])):
    (x, y, w, h), (x2, y2, w2, h2) = r1, r2

    if (
        min(abs(y2 + h2 - y), abs(y + h - y2)) < 8
        and min(abs(x2 - x), abs(x2 + w2 - x - w)) < 8
    ):
        to_merge.append(i)

# actually merge the regions
for i in to_merge:
    (x, y, w, h), (x2, y2, w2, h2) = regions[i], regions[i + 1]
    regions[i] = None

    ul1_x = x
    ul1_y = y
    br1_x = x + w
    br1_y = y + h
    ul2_x = x2
    ul2_y = y2
    br2_x = x2 + w2
    br2_y = y2 + h2

    ul_x = min(ul1_x, ul2_x)
    ul_y = min(ul1_y, ul2_y)
    br_x = max(br1_x, br2_x)
    br_y = max(br1_y, br2_y)

    regions[i + 1] = (ul_x, ul_y, br_x - ul_x, br_y - ul_y)

# discard removed regions
regions = [r for r in regions if r is not None]
# sort by x coordinate
regions.sort(key=lambda r: r[0])
```

Now all that's left to do is cutting these regions from the captcha image. I'm including two pixels of padding on each side. Then we'll resize the letters to a fixed size (e.g. 20x20), to make it easier to feed them to the neural network.

```py
# collect letters
letters = []
for x, y, w, h in regions:
    x -= 2
    y -= 2
    w += 4
    h += 4

    # cut out letter
    letter = img[y : y + h, x : x + w]

    # resize larger axis to 20, preserving aspect ratio
    if w > h:
        letter = imutils.resize(letter, width=20)
    else:
        letter = imutils.resize(letter, height=20)

    # pad smaller axis to 20 while centering letter
    pad_w = int((20 - w) / 2.0)
    pad_h = int((20 - h) / 2.0)
    letter = cv2.copyMakeBorder(
        letter, pad_h, pad_h, pad_w, pad_w, cv2.BORDER_CONSTANT, value=(255, 255, 255)
    )

    # resize once more to fix incorrect size caused by integer rounding
    letter = cv2.resize(letter, (20, 20))

    letters.append(letter)
```

## Neural Network

For this subproblem, we are given an image of a letter which we want to recognize.

I'm using Keras to build, train and use a convolutional neural network, which works far better than out-of-the-box OCR libraries.

To successfully train the neural network, we need a lot of labeled training data, i.e. images of letters and the letter that is displayed. Instead of solving thousands of captchas by hand, we can use the fact that the website tells us the solution to the very first level when we fail it to collect a bunch of training data (I used about 80000 images of letters).

Given the training images in `data_imgs` and the corresponding labels in `data_labels`, we divide our data into training and testing data (as is common practice when training neural networks, so that we have a rating not subject to overfitting) and convert our labels to be one-hot encoded.

```py
# split data into train and test sets
x_train, x_test, y_train, y_test = sklearn.model_selection.train_test_split(data_imgs, data_labels, test_size=0.2)

# make labels one-hot encoded
lb = LabelBinarizer().fit(y_train)
y_train = lb.transform(y_train)
y_test = lb.transform(y_test)
```

Now we can build and train the actual network.

```py
# build the neural network
model = Sequential()

# first convolutional layer with max pooling
model.add(Conv2D(20, (5, 5), padding="same", input_shape=(20, 20, 1), activation="relu"))
model.add(MaxPooling2D(pool_size=(2, 2), strides=(2, 2)))

# second convolutional layer with max pooling
model.add(Conv2D(50, (5, 5), padding="same", activation="relu"))
model.add(MaxPooling2D(pool_size=(2, 2), strides=(2, 2)))

# fully connected layer with 500 nodes
model.add(Flatten())
model.add(Dense(500, activation="relu"))

# output layer with 35 nodes (one for each possible character)
model.add(Dense(35, activation="softmax"))

# compile into a tensorflow model
model.compile(loss="categorical_crossentropy", optimizer="adam", metrics=["accuracy"])

# train on training data, while validating on test data
model.fit(x_train, y_train, validation_data=(x_test, y_test), batch_size=32, epochs=10, verbose=1)

# save trained model to disk
model.save("model.hdf5")
```

After 10 epochs of training (should only take a couple of minutes) on my training data, the model reached 99.97% accuracy on the test set, nice!

To use the trained model, all we have to do is load the model using `keras.models.load_model`, then pass images to it using `model.predict(letter_image)`.

## Flag

After putting both parts together and adding code that interacts with the server (see below), we let it run for a couple of minutes and get the flag: `CSCG{Y0UR_B0T_S0LV3D_THE_CAPTCHA}`

## Complete Code

`util.py` contains some common functionality to process images:

```py
from base64 import b64decode
from io import BytesIO
from os import listdir
from os.path import split

import cv2
import imutils
import numpy as np
from PIL import Image


def preprocess_and_split(img):
    """Preprocess a captcha image and split it into letters."""
    # pad image
    img = cv2.copyMakeBorder(img, 20, 20, 20, 20, cv2.BORDER_CONSTANT, value=(255, 255, 255))

    # grayscale
    img = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # white on black
    img = cv2.threshold(img, 80, 255, cv2.THRESH_BINARY_INV)[1]

    # contours
    contours = cv2.findContours(img, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)[0]

    # extract regions
    regions = []
    for i, contour in enumerate(contours):
        x, y, w, h = cv2.boundingRect(contour)
        if w / h > 1.35 if h > 15 else w / h > 1.5:
            w //= 2
            regions.append((x, y, w, h))
            regions.append((x + w, y, w, h))
        else:
            regions.append((x, y, w, h))

    # sort by x coordinate
    regions.sort(key=lambda r: r[0])

    # determine which regions to merge, to merge i and its dot
    to_merge = []
    for i, (r1, r2) in enumerate(zip(regions, regions[1:])):
        (x, y, w, h), (x2, y2, w2, h2) = r1, r2

        if (
            min(abs(y2 + h2 - y), abs(y + h - y2)) < 8
            and min(abs(x2 - x), abs(x2 + w2 - x - w)) < 8
        ):
            to_merge.append(i)

    # actually merge the regions
    for i in to_merge:
        (x, y, w, h), (x2, y2, w2, h2) = regions[i], regions[i + 1]
        regions[i] = None

        ul1_x = x
        ul1_y = y
        br1_x = x + w
        br1_y = y + h
        ul2_x = x2
        ul2_y = y2
        br2_x = x2 + w2
        br2_y = y2 + h2

        ul_x = min(ul1_x, ul2_x)
        ul_y = min(ul1_y, ul2_y)
        br_x = max(br1_x, br2_x)
        br_y = max(br1_y, br2_y)

        regions[i + 1] = (ul_x, ul_y, br_x - ul_x, br_y - ul_y)

    # discard removed regions
    regions = [r for r in regions if r is not None]

    # sort by x coordinate
    regions.sort(key=lambda r: r[0])

    # collect letters
    letters = []
    for x, y, w, h in regions:
        x -= 2
        y -= 2
        w += 4
        h += 4

        # cut out letter
        letter = img[y : y + h, x : x + w]

        # resize larger axis to 20, preserving aspect ratio
        if w > h:
            letter = imutils.resize(letter, width=20)
        else:
            letter = imutils.resize(letter, height=20)

        # pad smaller axis to 20 while centering letter
        pad_w = int((20 - w) / 2.0)
        pad_h = int((20 - h) / 2.0)
        letter = cv2.copyMakeBorder(
            letter, pad_h, pad_h, pad_w, pad_w, cv2.BORDER_CONSTANT, value=(255, 255, 255)
        )

        # resize once more to fix incorrect size caused by integer rounding
        letter = cv2.resize(letter, (20, 20))

        letters.append(letter)

    return letters


def base64_to_cv(data):
    """Convert base64 image data into a cv image."""
    assert data.startswith("data:image/png;base64,")
    raw = b64decode(data[22:])

    with BytesIO(raw) as b:
        return np.array(Image.open(b).convert("RGB"))


def get_filename(prefix, suffix=""):
    """Return a path to a nonexistent file with the given prefix and suffix."""
    d, pre = split(prefix)

    nums = []
    for f in listdir(d):
        if f.startswith(pre) and f.endswith(suffix):
            try:
                nums.append(int(f[len(pre) + 1 : -len(suffix)]))
            except (ValueError, IndexError):
                pass

    if nums:
        num = max(nums) + 1
    else:
        num = 0

    return prefix + "_" + str(num) + suffix
```

`sample.py` grabs training data from the webserver:

```py
#!/usr/bin/env python

from PIL import Image
from requests_html import HTMLSession

from util import base64_to_cv, get_filename, preprocess_and_split


def main():
    # fetch and store samples
    while True:
        # fetch
        img, text = fetch_sample()

        # split
        split = preprocess_and_split(img)

        # split was incorrect, discard
        if len(text) != len(split):
            continue

        # save all letters as samples
        for letter, img in zip(text, split):
            f = get_filename("samples/" + letter, ".png")
            Image.fromarray(img).save(f)


def fetch_sample():
    """Download a captcha image and its solution."""
    url = "http://hax1.allesctf.net:9200/captcha/0"
    with HTMLSession() as s:

        # get image
        resp = s.get(url)
        img = resp.html.find("img")[0].attrs["src"]

        # get solution
        resp = s.post(url, data={"0": "asdf"})
        text = resp.html.find("b")[0].text

        return base64_to_cv(img), text


if __name__ == "__main__":
    main()
```

`train.py` trains the neural network on the sampled data:

```py
#!/usr/bin/env python

import os
import os.path
import pickle

import cv2
import numpy as np
from keras.layers.convolutional import Conv2D, MaxPooling2D
from keras.layers.core import Dense, Flatten
from keras.models import Sequential
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelBinarizer

data = []
labels = []

# loop over the input images
for image_file in os.listdir("samples"):
    # load the image and convert it to black and white
    image = cv2.imread("samples/" + image_file)
    image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    image = cv2.threshold(image, 80, 255, cv2.THRESH_BINARY)[1]

    # add third dimension so we can pass it to keras
    image = np.expand_dims(image, axis=2)

    # label saved as first char of filename
    label = image_file[0]

    data.append(image)
    labels.append(label)

# we should have training images of all possible characters
assert len(set(labels)) == 35

# scale raw pixel intensities to [0, 1]
data = np.array(data, dtype="float") / 255.0
labels = np.array(labels)

# split data into train and test sets
x_train, x_test, y_train, y_test = train_test_split(data, labels, test_size=0.2, random_state=0)

# make labels one-hot encoded
lb = LabelBinarizer().fit(y_train)
y_train = lb.transform(y_train)
y_test = lb.transform(y_test)

# save mapping from labels to one-hot encoded
with open("labels.dat", "wb") as f:
    pickle.dump(lb, f)

# build the neural network
model = Sequential()

# first convolutional layer with max pooling
model.add(Conv2D(20, (5, 5), padding="same", input_shape=(20, 20, 1), activation="relu"))
model.add(MaxPooling2D(pool_size=(2, 2), strides=(2, 2)))

# second convolutional layer with max pooling
model.add(Conv2D(50, (5, 5), padding="same", activation="relu"))
model.add(MaxPooling2D(pool_size=(2, 2), strides=(2, 2)))

# fully connected layer with 500 nodes
model.add(Flatten())
model.add(Dense(500, activation="relu"))

# output layer with 35 nodes (one for each possible character)
model.add(Dense(35, activation="softmax"))

# compile into a tensorflow model
model.compile(loss="categorical_crossentropy", optimizer="adam", metrics=["accuracy"])

# train on training data, while validating on test data
model.fit(x_train, y_train, validation_data=(x_test, y_test), batch_size=32, epochs=10, verbose=1)

# save trained model to disk
model.save("model.hdf5")
```

`solve.py` uses the trained network to solve the challenge:

```py
#!/usr/bin/env python

import pickle

import numpy as np
from keras.models import load_model
from requests_html import HTMLSession

from util import base64_to_cv, preprocess_and_split


def main():
    init()

    url = "http://hax1.allesctf.net:9200/captcha/0"
    while True:
        with HTMLSession() as sess:
            resp = sess.get(url)

            while True:

                # get images
                imgs = [base64_to_cv(x.attrs["src"]) for x in resp.html.find("img")]

                # solve
                solves = [solve_captcha(x) for x in imgs]

                # submit solution
                solve = {str(i): s for i, s in enumerate(solves)}
                print(solve)
                resp = sess.post(resp.url, data=solve)

                print(resp)
                print(resp.url)

                # check if we have the flag
                if "captcha/4" in resp.url:
                    print(resp.text)
                    exit()

                # try again if we failed
                if "fail" in resp.url:
                    break

        print("\n---------- FAILED ----------\n")


def init():
    """Load model."""
    global lb, model

    # load mapping from labels to one-hot encoded
    with open("labels.dat", "rb") as f:
        lb = pickle.load(f)

    # load trained neural network
    model = load_model("model.hdf5")


def solve_captcha(img):
    """Solve a captcha image."""
    split = preprocess_and_split(img)

    predictions = []
    for letter_image in split:

        # add more dimensions so we can pass if to keras
        letter_image = np.expand_dims(letter_image, axis=2)
        letter_image = np.expand_dims(letter_image, axis=0)

        prediction = model.predict(letter_image)

        # convert prediction to character
        letter = lb.inverse_transform(prediction)[0]
        predictions.append(letter)

    text = "".join(predictions)
    print("Prediction:", text)

    return text


if __name__ == "__main__":
    main()
```
