from django.db import models
from django.utils.translation import ugettext_lazy as _
from django_countries.fields import CountryField

from django.contrib.auth.models import AbstractUser
from django.utils.translation import ugettext as _
from django.contrib.contenttypes.models import ContentType

from django.conf import settings

_custom_perm =  (
            ('can_view', _('Permesso in lettura')),
            ('can_view_his_own', _('Permesso in lettura esclusivamente dei propri inserimenti')),
            ('can_change', _('Permesso in modifica')),
            ('can_change_his_own', _('Permesso in modifica esclusivamente dei propri inserimenti')),
            ('can_delete', _('Permesso in cancellazione')),
            ('can_delete_his_own', _('Permesso in cancellazione  esclusivamente dei propri inserimenti')),
                )

class User(AbstractUser):
    GENDER= (
                ( 'male', _('Maschio')),
                ( 'female', _('Femmina')),
                ( 'other', _('Altro')),
            )
    
    is_active = models.BooleanField(_('attivo'), default=True)
    email = models.EmailField(_('email address'), blank=True, null=True)
    matricola = models.CharField(_('Matricola'), max_length=6, 
                                 blank=True, null=True,
                                 help_text="come rappresentata su CSA")
    first_name = models.CharField(_('Nome'), max_length=30, blank=True, null=True)
    last_name = models.CharField(_('Cognome'), max_length=30,
                                 blank=True, null=True)   
    codice_fiscale = models.CharField(_('Codice Fiscale'), max_length=16, 
                                      blank=True, null=True)  
    gender    = models.CharField(_('Genere'), choices=GENDER,
                                 max_length=12, blank=True, null=True)
    location = CountryField(_('Luogo di nascita'), max_length=30,
                            blank=True, null=True)
    birth_date = models.DateField(_('Data di nascita'), null=True, blank=True)
    
    #short_description = models.CharField(_('Descrizione breve'), max_length=33, blank=True, null=True)    
    #bio = models.TextField(_('Biografia, note'), max_length=2048, blank=True, null=True)
    # avatar  = models.ImageField(_('Avatar, foto'), upload_to='avatars/', null=True, blank=True)
    # webpage_url = models.CharField(_('Pagina web'), max_length=512, blank=True, null=True)    
    class Meta:
        ordering = ['username']
        verbose_name_plural = _("Accounts")
        permissions = _custom_perm
    
    def __str__(self):
        return '%s - %s %s' % (self.matricola,
                               self.first_name, self.last_name)
