import uuid

from django.conf import settings
from django.shortcuts import render
from django.views.generic.base import View, TemplateView
from django.core.urlresolvers import reverse
from django import http
from django.contrib.auth import authenticate, login
from django.forms.util import ErrorList
from django.forms.forms import NON_FIELD_ERRORS
from django.http import HttpResponseRedirect

from pybitid import bitid

from models import Nonce
from forms import BitIdForm

import logging
import json 

logger = logging.getLogger()

class BitIdView(View):
    DEFAULT_HOSTNAME = 'example.com'

    def get_callback_uri(self, request):
        hostname = request.META.get('HTTP_HOST', self.DEFAULT_HOSTNAME)
        secure = True
        if settings.DEBUG:
            secure = False
        return 'http%s://%s%s' % ('s' if secure else '', hostname, reverse('djbitid_callback'))
    

class BitIdChallenge(BitIdView):
    template_name = 'djbitid/challenge.html'

    def get(self, request):
        """
        This function initializes the authentication process 
        It builds a challenge which is sent to the client
        """

        # Creates a new nonce associated to this session

        sid = request.session._get_or_create_session_key()

        nonce = Nonce(sid=sid)
        nonce.save()

        # Gets the callback uri
        callback_uri = self.get_callback_uri(request)

        # Builds the challenge (bitid uri) 
        bitid_uri = bitid.build_uri(callback_uri, nonce.nid)

        # Gets the qrcode uri
        qrcode = bitid.qrcode(bitid_uri)

        context = {
            "callback_uri": callback_uri,
            "bitid_uri": bitid_uri,
            "qrcode": qrcode
        }

        return render(request, self.template_name, context)


class BitIdCallback(BitIdView):
    template_name = 'djbitid/callback.html'

    def get(self, request):
        form = BitIdForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        """
        This function validates the response sent by the client about the challenge
        This is the route called by the bitcoin wallet when the challenge has been signed
        """

        # Retrieves the callback uri
        callback_uri = self.get_callback_uri(request)
        
        # Extracts data from the posted request
        try:
            data = json.loads(request.body)                                         
            bitid_uri = data.get("uri")
            signature = data.get("signature")                                       
            address   = data.get("address")                                         
        except Exception:
            bitid_uri = request.POST.get("uri")
            signature = request.POST.get("signature")                               
            address   = request.POST.get("address")    

        logger.info('bitid_uri=%s' % bitid_uri)
        logger.info('callback_uri=%s' % self.get_callback_uri(request))
        logger.info('signature=%s' % signature)
        logger.info('address=%s' % address)

        errors = []

        user = authenticate(bitid_uri=bitid_uri, callback_uri=callback_uri,
                            signature=signature, address=address, errors=errors)

        if user is not None:
            logger.info('is_auth?=%s' % user.is_authenticated())
            user.save()
            #login(request, user)
            #return render(request, self.template_name, {'user': user })
            return HttpResponseRedirect(reverse('djbitid_challenge'))
        else:
            form = BitIdForm(request.POST)
            form.full_clean()
            for error in errors:
                form._errors[NON_FIELD_ERRORS] = form.error_class([error])
            #return HttpResponseRedirect(reverse('djbitid_challenge'))
            #return HttpResponseRedirect(reverse('login'))
            #return HttpResponseRedirect(reverse('djbitid_challenge'))
            qrcode = bitid.qrcode(bitid_uri)
            return render(request, self.template_name, {'form': form, 'bitid_uri': bitid_uri, 'qrcode': qrcode })
