from django.shortcuts import render, redirect
from django.contrib import messages

import STreifen.models as mymodels
import STreifen.forms as myforms
from ..models import *
from ..forms import *
from .timeline import stix2timeline

import re, json, requests

def stix_view(request):
    form = InputForm()
    if request.method == "POST":
        #print(request.POST)
        if 'timeline' in request.POST:
            form = InputForm(request.POST)
            if form.is_valid():
                stix = form.cleaned_data["input"]
                data = stix2timeline(json.loads(stix))
                c = {
                    "items":data["items"],
                    "groups":data["groups"],
                }
                return render(request, 'timeline_viz.html', c)

        elif 'parse_url' in request.POST:
            form = InputForm(request.POST)
            if form.is_valid():
                b = {"objects":[]}
                urls = form.cleaned_data["input"]
                for url in urls.split("\n"):
                    if not re.match("^https?://.+", url):
                        messages.add_message(
                            request,
                            messages.ERROR,
                            'ERROR: Invalid Input -> '+url,
                        )
                    else:
                        res = requests.get(url.strip())
                        if res:
                            j = res.json()
                            if "objects" in j:
                                for o in j["objects"]:
                                    if not o in b["objects"]:
                                        b["objects"].append(o)
                c = {
                    "stix":json.dumps(b, indent=2),
                }
                return render(request, 'stix_viz.html', c)
    c = {
        "form":form,
    }
    return render(request, 'stix_view.html', c)

