from django.http import HttpResponse, Http404, HttpResponseRedirect, HttpResponseNotFound

from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from .models import *
from .forms import *

from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ValidationError

from django.template import RequestContext
from django.core.urlresolvers import reverse
from .functions import Form_save, Form_update

from django.contrib.auth import authenticate, login, logout
# from dal import autocomplete
# 
# class UserAutocomplete(autocomplete.Select2QuerySetView):
    # def get_queryset(self):
        # if not self.request.user.is_authenticated():
            # return User.objects.none()
        # qs = User.objects.all()
        # if self.q:
            # qs = qs.filter(  
                             # username__icontains=self.q 
                          # )
        # return qs

# def Login(request):
    # if request.method == 'GET':
        # diz = {}
        # return render(request, 'login.html', diz)
    # else:
        # validate auth
        # username = request.POST['username']
        # password = request.POST['password']
        # user = authenticate(username=username, password=password)
        # if user is not None:
            # if user.is_active:
                # login(request, user)
                # return HttpResponseRedirect(reverse('accounts:user_profile', args=[]))
                # #return HttpResponseRedirect(reverse('callcenter:richiami', args=[]))
        # diz = {'message': 'Credenziali errate'}
        # return render(request, 'login.html', diz)


@login_required
def Logout(request):
    logout(request)
    return render(request, 'login.html')

@login_required
def UserProfile(request):
    utente = get_object_or_404(User, pk=request.user.pk)
    d = { 
            'utente': utente,
            'skills': UserSkill.objects.filter(user=utente),
            'shortcuts': UserUrlShortcut.objects.filter(user=utente),
        }
    return render(request, 'user_profile.html', d)

# @login_required
# def UserCalendar(request):
    # utente = get_object_or_404(User, pk=request.user.pk)
    # d = { 
            # 'utente': utente,
        # }
    # return render(request, 'calendar.html', d)

# @login_required
# def OnlineUsers(request):
    # utente = get_object_or_404(User, pk=request.user.pk)
    # d = { 
            # 'utente': utente,
        # }
    # return render(request, 'utenti_online.html', d)

@login_required
def EditUserProfile(request):
    utente        = get_object_or_404(User, pk=request.user.pk)
    template_name = 'user_profile_form.html'
    d = { 
            'utente': utente,
            'form'  : UserForm(initial=utente.__dict__)
        }
    
    # leggo i campi del form in stdout
    #~ for i in UserForm(initial=utente.__dict__).__dict__['fields']:
        #~ print(i)
    
    if request.POST:
        modelform = UserForm
        model     = User
        #~ return HttpResponse('ok')
        
        data = dict(request.POST.items())
        
        #~ if request.FILES:
            #~ data.update( dict(request.FILES.items()) )
        
        # preserve staff status if available
        if utente.is_staff:
            data['is_staff'] = True        
        
        form = modelform(data=data, instance=utente )
        
        #~ print(data)
        
        if data['new_password'] != data['verify_password']:
            form.add_error('new_password', ValidationError(_('Le password non corrispondono'), code='invalid'))
            form.add_error('verify_password', ValidationError(_('Le password non corrispondono'), code='invalid'))
            d['form'] = form            
            return render(request, template_name, d)
        
        if not utente.check_password(data['old_password']):
            form.add_error('old_password', ValidationError(_('La password non è corretta!'), code='invalid'))
            d['form'] = form
            return render(request, template_name, d)
        
        if data.get('csrfmiddlewaretoken'): 
            del(data['csrfmiddlewaretoken'])

        if form.is_valid():
            form.save()
            if data.get('new_password'):
                utente.set_password(data['new_password'])
            else:
                utente.set_password(data['old_password'])
            utente.save()
            
            if request.FILES.get('avatar'):
                # se immagine profilo salvo anche questa
                avatar = request.FILES['avatar']
                utente.avatar = avatar
                utente.save()
            
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(request, utente)
            
            return HttpResponseRedirect(reverse('accounts:user_profile', args=[]))
        else:
            print(form.errors)
            d['form'] = form
    
    return render(request, template_name, d)

